package channels

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/utils"
)

// Bitrix24Channel implements the Channel interface for Bitrix24 CRM
// using HTTP webhook for receiving messages and REST API for sending.
type Bitrix24Channel struct {
	*BaseChannel
	config          config.Bitrix24Config
	httpServer      *http.Server
	httpClient      *http.Client
	rateLimiter     *time.Ticker
	rateMu          sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	diskFolderCache sync.Map // chatID → folderID string
	seenEvents      sync.Map // eventKey → expiry time.Time
}

// NewBitrix24Channel creates a new Bitrix24 channel instance.
func NewBitrix24Channel(cfg config.Bitrix24Config, messageBus *bus.MessageBus) (*Bitrix24Channel, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("bitrix24 domain is required")
	}
	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("bitrix24 webhook_secret is required")
	}
	if cfg.BotID == "" {
		return nil, fmt.Errorf("bitrix24 bot_id is required")
	}

	base := NewBaseChannel("bitrix24", cfg, messageBus, cfg.AllowFrom)

	return &Bitrix24Channel{
		BaseChannel: base,
		config:      cfg,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		rateLimiter: time.NewTicker(time.Second), // 1 req/sec
	}, nil
}

// Start launches the HTTP webhook server for receiving Bitrix24 events.
func (c *Bitrix24Channel) Start(ctx context.Context) error {
	logger.InfoC("bitrix24", "Starting Bitrix24 channel (Webhook Mode)")

	c.ctx, c.cancel = context.WithCancel(ctx)

	mux := http.NewServeMux()
	path := c.config.WebhookPath
	if path == "" {
		path = "/webhook/bitrix24"
	}
	mux.HandleFunc(path, c.webhookHandler)

	addr := fmt.Sprintf("%s:%d", c.config.WebhookHost, c.config.WebhookPort)
	c.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		logger.InfoCF("bitrix24", "Bitrix24 webhook server listening", map[string]interface{}{
			"addr": addr,
			"path": path,
		})
		if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.ErrorCF("bitrix24", "Webhook server error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}()

	// Periodic cleanup of expired deduplication entries
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				c.seenEvents.Range(func(k, v interface{}) bool {
					if now.After(v.(time.Time)) {
						c.seenEvents.Delete(k)
					}
					return true
				})
			case <-c.ctx.Done():
				return
			}
		}
	}()

	c.setRunning(true)

	// Register bot commands if configured (fire-and-forget)
	if len(c.config.Commands) > 0 {
		go c.registerCommands()
	}

	logger.InfoC("bitrix24", "Bitrix24 channel started (Webhook Mode)")
	return nil
}

// Stop gracefully shuts down the HTTP server and rate limiter.
func (c *Bitrix24Channel) Stop(ctx context.Context) error {
	logger.InfoC("bitrix24", "Stopping Bitrix24 channel")

	if c.cancel != nil {
		c.cancel()
	}

	if c.rateLimiter != nil {
		c.rateLimiter.Stop()
	}

	if c.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorCF("bitrix24", "Webhook server shutdown error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	c.setRunning(false)
	logger.InfoC("bitrix24", "Bitrix24 channel stopped")
	return nil
}

// ============================================================================
// Webhook Handler (Issue #3)
// ============================================================================

// webhookHandler handles incoming Bitrix24 webhook requests.
// Bitrix24 sends form-urlencoded POST with nested keys like data[PARAMS][MESSAGE].
func (c *Bitrix24Channel) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.ErrorCF("bitrix24", "Failed to read request body", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Verify webhook secret from query parameter
	secret := r.URL.Query().Get("secret")
	if !c.verifySecret(secret) {
		logger.WarnC("bitrix24", "Invalid webhook secret")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Parse the form-urlencoded body
	event := c.parseWebhookBody(string(body))

	// Event deduplication: Bitrix24 can fire duplicate webhook events on retries
	const dedupTTL = 5 * time.Minute

	dedupID := event.Params["MESSAGE_ID"]
	if dedupID == "" {
		dedupID = event.Params["CMD_MESSAGE_ID"]
	}
	if dedupID != "" {
		key := event.Event + ":" + dedupID
		now := time.Now()
		expiry := now.Add(dedupTTL)
		if prev, loaded := c.seenEvents.LoadOrStore(key, expiry); loaded {
			if now.Before(prev.(time.Time)) {
				logger.DebugCF("bitrix24", "Dropping duplicate event",
					map[string]interface{}{"key": key})
				w.WriteHeader(http.StatusOK)
				return
			}
			c.seenEvents.Store(key, expiry)
		}
	}

	// Return 200 immediately, process asynchronously
	w.WriteHeader(http.StatusOK)

	go c.processEvent(event)
}

// bitrix24Event represents a parsed Bitrix24 webhook event.
type bitrix24Event struct {
	Event  string
	Params map[string]string
	User   map[string]string
	Bot    map[string]string
	Auth   map[string]string
}

// parseWebhookBody parses Bitrix24's form-urlencoded body with nested keys.
func (c *Bitrix24Channel) parseWebhookBody(body string) bitrix24Event {
	event := bitrix24Event{
		Params: make(map[string]string),
		User:   make(map[string]string),
		Bot:    make(map[string]string),
		Auth:   make(map[string]string),
	}

	values, err := url.ParseQuery(body)
	if err != nil {
		logger.ErrorCF("bitrix24", "Failed to parse form body", map[string]interface{}{
			"error": err.Error(),
		})
		return event
	}

	for key, vals := range values {
		if len(vals) == 0 {
			continue
		}
		val := vals[0]

		switch {
		case key == "event":
			event.Event = val
		case strings.HasPrefix(key, "data[PARAMS]["):
			field := extractBracketField(key, "data[PARAMS][")
			if field != "" {
				event.Params[field] = val
			}
		case strings.HasPrefix(key, "data[USER]["):
			field := extractBracketField(key, "data[USER][")
			if field != "" {
				event.User[field] = val
			}
		case strings.HasPrefix(key, "data[BOT]"):
			// data[BOT][130387][BOT_ID] format — extract the field name
			field := extractNestedBracketField(key)
			if field != "" {
				event.Bot[field] = val
			}
		case strings.HasPrefix(key, "data[COMMAND]"):
			// data[COMMAND][0][COMMAND] format
			field := extractNestedBracketField(key)
			if field != "" {
				event.Params["CMD_"+field] = val
			}
		case strings.HasPrefix(key, "auth["):
			field := extractBracketField(key, "auth[")
			if field != "" {
				event.Auth[field] = val
			}
		}
	}

	return event
}

// extractBracketField extracts the field name from a key like "prefix[FIELD]".
func extractBracketField(key, prefix string) string {
	rest := key[len(prefix):]
	idx := strings.Index(rest, "]")
	if idx > 0 {
		return rest[:idx]
	}
	return ""
}

// extractNestedBracketField extracts the last bracket field from nested keys
// like "data[BOT][130387][BOT_ID]" → "BOT_ID".
func extractNestedBracketField(key string) string {
	parts := strings.Split(key, "[")
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-1]
	return strings.TrimSuffix(last, "]")
}

// verifySecret verifies the webhook secret using constant-time comparison.
func (c *Bitrix24Channel) verifySecret(secret string) bool {
	if secret == "" {
		return false
	}
	expected := []byte(c.config.WebhookSecret)
	received := []byte(secret)
	if len(expected) != len(received) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, received) == 1
}

// processEvent routes the parsed event to the appropriate handler.
func (c *Bitrix24Channel) processEvent(event bitrix24Event) {
	switch event.Event {
	case "ONIMMESSAGEADD", "ONIMBOTMESSAGEADD":
		c.handleMessage(event)
	case "ONIMCOMMANDADD":
		c.handleCommand(event)
	default:
		logger.DebugCF("bitrix24", "Ignoring unhandled event", map[string]interface{}{
			"event": event.Event,
		})
	}
}

// handleMessage processes an incoming message event.
func (c *Bitrix24Channel) handleMessage(event bitrix24Event) {
	fromUserID := firstNonEmpty(
		event.Params["FROM_USER_ID"],
		event.Params["AUTHOR_ID"],
		event.User["ID"],
	)
	if fromUserID == "" {
		logger.WarnC("bitrix24", "Message event missing author ID")
		return
	}

	// Skip bot's own messages to avoid infinite loop
	if fromUserID == event.Bot["BOT_ID"] || fromUserID == c.config.BotID {
		logger.DebugC("bitrix24", "Skipping bot's own message")
		return
	}

	messageText := event.Params["MESSAGE"]

	dialogID := firstNonEmpty(
		event.Params["DIALOG_ID"],
		event.Params["TO_CHAT_ID"],
		fromUserID,
	)

	// Group chat mention filter: only respond if @mentioned (unless GroupRespondAll)
	isGroupChat := strings.HasPrefix(dialogID, "chat:")
	if isGroupChat && !c.config.GroupRespondAll {
		mentionTag := "[USER=" + c.config.BotID + "]"
		if !strings.Contains(messageText, mentionTag) {
			logger.DebugCF("bitrix24", "Ignoring group message: bot not mentioned",
				map[string]interface{}{
					"dialog_id": dialogID,
					"bot_id":    c.config.BotID,
				})
			return
		}
	}

	// Send typing indicator immediately (fire-and-forget)
	go c.sendTyping(dialogID)

	userName := firstNonEmpty(event.User["NAME"], "User"+fromUserID)
	senderID := fromUserID

	// Handle file attachments (Issue #10)
	var mediaPaths []string
	var localFiles []string

	defer func() {
		for _, f := range localFiles {
			if err := os.Remove(f); err != nil {
				logger.DebugCF("bitrix24", "Failed to cleanup temp file", map[string]interface{}{
					"file":  f,
					"error": err.Error(),
				})
			}
		}
	}()

	// Check for file attachment via FILES count or file ID in PARAMS
	fileIDStr := event.Params["PARAMS"]
	filesCount := event.Params["FILES"]

	if fileIDStr != "" && (filesCount != "" || strings.TrimSpace(messageText) == "") {
		localPath, category := c.downloadAttachment(fileIDStr)
		if localPath != "" {
			localFiles = append(localFiles, localPath)
			mediaPaths = append(mediaPaths, localPath)

			if category != "" {
				messageText += fmt.Sprintf(" [%s attachment]", category)
			}
		}
	}

	if strings.TrimSpace(messageText) == "" && len(mediaPaths) == 0 {
		logger.DebugC("bitrix24", "Empty message, skipping")
		return
	}

	metadata := map[string]string{
		"platform":   "bitrix24",
		"message_id": event.Params["MESSAGE_ID"],
		"user_name":  userName,
		"dialog_id":  dialogID,
	}

	logger.DebugCF("bitrix24", "Received message", map[string]interface{}{
		"sender_id":    senderID,
		"dialog_id":    dialogID,
		"has_media":    len(mediaPaths) > 0,
		"preview":      utils.Truncate(messageText, 50),
	})

	c.HandleMessage(senderID, dialogID, messageText, mediaPaths, metadata)
}

// downloadAttachment fetches file info and downloads the attachment.
// Returns the local file path and category (image/voice/video/document/file).
func (c *Bitrix24Channel) downloadAttachment(fileID string) (string, string) {
	// Fetch file info via disk.file.get
	result, err := c.callAPI(c.ctx, "disk.file.get", map[string]string{
		"id": fileID,
	})
	if err != nil {
		logger.ErrorCF("bitrix24", "Failed to fetch file info", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
		return "", ""
	}

	var fileInfo struct {
		ID          int    `json:"ID"`
		Name        string `json:"NAME"`
		Size        int    `json:"SIZE"`
		ContentType string `json:"TYPE"`
		DownloadURL string `json:"DOWNLOAD_URL"`
	}
	if err := json.Unmarshal(result, &fileInfo); err != nil {
		logger.ErrorCF("bitrix24", "Failed to parse file info", map[string]interface{}{
			"error": err.Error(),
		})
		return "", ""
	}

	if fileInfo.DownloadURL == "" {
		logger.WarnCF("bitrix24", "File has no download URL", map[string]interface{}{
			"file_id": fileID,
			"name":    fileInfo.Name,
		})
		return "", ""
	}

	// Categorize by MIME type
	category := categorizeFile(fileInfo.ContentType, fileInfo.Name)

	// Download the file
	localPath := utils.DownloadFile(fileInfo.DownloadURL, fileInfo.Name, utils.DownloadOptions{
		LoggerPrefix: "bitrix24",
	})

	if localPath == "" {
		return "", ""
	}

	logger.InfoCF("bitrix24", "Downloaded attachment", map[string]interface{}{
		"name":     fileInfo.Name,
		"category": category,
		"size":     fileInfo.Size,
	})

	return localPath, category
}

// categorizeFile determines the attachment category from MIME type and filename.
func categorizeFile(mimeType, filename string) string {
	lower := strings.ToLower(mimeType)
	switch {
	case strings.HasPrefix(lower, "image/"):
		return "image"
	case strings.HasPrefix(lower, "audio/"), strings.HasPrefix(lower, "voice"):
		return "voice"
	case strings.HasPrefix(lower, "video/"):
		return "video"
	case strings.HasPrefix(lower, "application/pdf"),
		strings.HasPrefix(lower, "application/msword"),
		strings.HasPrefix(lower, "application/vnd."):
		return "document"
	}

	// Fallback: check extension
	lowerName := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lowerName, ".jpg"), strings.HasSuffix(lowerName, ".jpeg"),
		strings.HasSuffix(lowerName, ".png"), strings.HasSuffix(lowerName, ".gif"):
		return "image"
	case strings.HasSuffix(lowerName, ".mp3"), strings.HasSuffix(lowerName, ".ogg"),
		strings.HasSuffix(lowerName, ".m4a"), strings.HasSuffix(lowerName, ".wav"),
		strings.HasSuffix(lowerName, ".opus"):
		return "voice"
	case strings.HasSuffix(lowerName, ".mp4"), strings.HasSuffix(lowerName, ".webm"):
		return "video"
	case strings.HasSuffix(lowerName, ".pdf"), strings.HasSuffix(lowerName, ".doc"),
		strings.HasSuffix(lowerName, ".docx"):
		return "document"
	}

	return "file"
}

// handleCommand processes a bot command event (ONIMCOMMANDADD).
func (c *Bitrix24Channel) handleCommand(event bitrix24Event) {
	commandName := firstNonEmpty(event.Params["CMD_COMMAND"], event.Params["COMMAND"])
	if commandName == "" {
		logger.WarnC("bitrix24", "Command event missing command name")
		return
	}

	fromUserID := firstNonEmpty(
		event.Params["CMD_USER_ID"],
		event.Params["FROM_USER_ID"],
		event.User["ID"],
	)
	dialogID := firstNonEmpty(
		event.Params["CMD_DIALOG_ID"],
		event.Params["DIALOG_ID"],
		fromUserID,
	)
	commandArgs := event.Params["CMD_COMMAND_PARAMS"]

	content := "/" + commandName
	if commandArgs != "" {
		content += " " + commandArgs
	}

	metadata := map[string]string{
		"platform":   "bitrix24",
		"is_command": "true",
		"command":    commandName,
		"message_id": event.Params["CMD_MESSAGE_ID"],
	}

	logger.InfoCF("bitrix24", "Received command", map[string]interface{}{
		"command":   commandName,
		"sender_id": fromUserID,
		"args":      commandArgs,
	})

	go c.sendTyping(dialogID)

	c.HandleMessage(fromUserID, dialogID, content, nil, metadata)
}

// ============================================================================
// Bot Command Registration (Issue #8)
// ============================================================================

// registerCommands registers bot commands on startup via imbot.command.register.
// Errors don't block the channel — commands are a nice-to-have.
func (c *Bitrix24Channel) registerCommands() {
	for _, cmd := range c.config.Commands {
		// Build webhook URL for command events
		path := c.config.WebhookPath
		if path == "" {
			path = "/webhook/bitrix24"
		}
		webhookURL := fmt.Sprintf("%s%s?secret=%s",
			c.webhookBaseURL(), path, c.config.WebhookSecret)

		common := "N"
		if cmd.Common {
			common = "Y"
		}
		hidden := "N"
		if cmd.Hidden {
			hidden = "Y"
		}

		params := map[string]string{
			"COMMAND":           cmd.Command,
			"COMMON":            common,
			"HIDDEN":            hidden,
			"EXTRANET_SUPPORT":  "N",
			"EVENT_COMMAND_ADD": webhookURL,
			"LANG[0][LANGUAGE_ID]": "en",
			"LANG[0][TITLE]":       cmd.Title,
			"LANG[1][LANGUAGE_ID]": "de",
			"LANG[1][TITLE]":       cmd.Title, // German fallback to English
		}
		if cmd.Description != "" {
			params["LANG[0][PARAMS]"] = cmd.Description
			params["LANG[1][PARAMS]"] = cmd.Description
		}
		if c.config.BotID != "" {
			params["BOT_ID"] = c.config.BotID
		}

		_, err := c.callAPI(c.ctx, "imbot.command.register", params)
		if err != nil {
			// Handle 409/already exists gracefully
			if strings.Contains(err.Error(), "COMMAND_ALREADY_EXISTS") ||
				strings.Contains(err.Error(), "409") {
				logger.DebugCF("bitrix24", "Command already registered", map[string]interface{}{
					"command": cmd.Command,
				})
			} else {
				logger.ErrorCF("bitrix24", "Failed to register command", map[string]interface{}{
					"command": cmd.Command,
					"error":   err.Error(),
				})
			}
		} else {
			logger.InfoCF("bitrix24", "Registered command", map[string]interface{}{
				"command": cmd.Command,
			})
		}
	}
}

// ============================================================================
// REST API Client (Issue #4)
// ============================================================================

// buildAPIURL constructs the Bitrix24 REST API URL for a method.
// Pattern: https://{domain}/rest/{userId}/{webhookSecret}/{method}
func (c *Bitrix24Channel) buildAPIURL(method string) string {
	return fmt.Sprintf("https://%s/rest/%s/%s/%s",
		c.config.Domain,
		c.config.UserID,
		c.config.WebhookSecret,
		method,
	)
}

// callAPIRaw executes a rate-limited POST to the Bitrix24 REST API.
// The caller must set req.URL and req.Header["Content-Type"] before calling.
func (c *Bitrix24Channel) callAPIRaw(ctx context.Context, req *http.Request) (json.RawMessage, error) {
	c.rateMu.Lock()
	select {
	case <-c.rateLimiter.C:
	case <-ctx.Done():
		c.rateMu.Unlock()
		return nil, ctx.Err()
	}
	c.rateMu.Unlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bitrix24 API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitrix24 API error (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
		Desc   string          `json:"error_description"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if apiResp.Error != "" {
		return nil, fmt.Errorf("bitrix24 API: %s — %s", apiResp.Error, apiResp.Desc)
	}

	return apiResp.Result, nil
}

// callAPI makes a rate-limited POST request to the Bitrix24 REST API.
func (c *Bitrix24Channel) callAPI(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	apiURL := c.buildAPIURL(method)

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	if c.config.ClientID != "" {
		form.Set("CLIENT_ID", c.config.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return c.callAPIRaw(ctx, req)
}

// callAPIJSON makes a rate-limited POST with JSON body for complex parameters.
func (c *Bitrix24Channel) callAPIJSON(ctx context.Context, method string, payload interface{}) (json.RawMessage, error) {
	apiURL := c.buildAPIURL(method)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return c.callAPIRaw(ctx, req)
}

// Send sends a message to Bitrix24 via imbot.message.add.
func (c *Bitrix24Channel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("bitrix24 channel not running")
	}

	// Convert Markdown to BBCode
	formatted := markdownToBBCode(msg.Content)

	// Split long messages if needed (Bitrix24 limit ~60K chars)
	fragments := utils.SplitMessage(formatted, 60000)

	for _, fragment := range fragments {
		params := map[string]string{
			"DIALOG_ID": msg.ChatID,
			"MESSAGE":   fragment,
			"SYSTEM":    "N",
		}
		if c.config.BotID != "" {
			params["BOT_ID"] = c.config.BotID
		}

		_, err := c.callAPI(ctx, "imbot.message.add", params)
		if err != nil {
			logger.ErrorCF("bitrix24", "Failed to send message", map[string]interface{}{
				"chat_id": msg.ChatID,
				"error":   err.Error(),
			})
			return err
		}
	}

	logger.DebugCF("bitrix24", "Message sent", map[string]interface{}{
		"chat_id":   msg.ChatID,
		"fragments": len(fragments),
	})
	return nil
}

// ============================================================================
// Typing Indicator (Issue #6)
// ============================================================================

// sendTyping sends a typing indicator to the chat.
// Best-effort: errors are logged at debug level only.
func (c *Bitrix24Channel) sendTyping(dialogID string) {
	params := map[string]string{
		"DIALOG_ID": dialogID,
	}
	if c.config.BotID != "" {
		params["BOT_ID"] = c.config.BotID
	}
	if _, err := c.callAPI(c.ctx, "imbot.chat.sendTyping", params); err != nil {
		logger.DebugCF("bitrix24", "Failed to send typing indicator",
			map[string]interface{}{"dialog_id": dialogID, "error": err.Error()})
	}
}

// ============================================================================
// File Upload (Issue #11)
// ============================================================================

// uploadFile uploads a file to Bitrix24 using the 3-step flow:
// 1. im.disk.folder.get (get/cache folder ID)
// 2. disk.folder.uploadfile (upload to folder)
// 3. Return [DISK=id] reference for embedding in messages
func (c *Bitrix24Channel) uploadFile(ctx context.Context, chatID, filePath string) (string, error) {
	// Step 1: Get chat folder ID (cached)
	folderID, err := c.getChatFolderID(ctx, chatID)
	if err != nil {
		return "", fmt.Errorf("failed to get folder ID: %w", err)
	}

	// Step 2: Upload file to folder
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	fileName := filepath.Base(filePath)
	encoded := base64.StdEncoding.EncodeToString(fileData)

	params := map[string]string{
		"id":          folderID,
		"data[NAME]":  fileName,
		"fileContent[]": fileName,
	}
	// The second fileContent[] value is the base64 data
	// We need to use form encoding with repeated keys
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	form.Add("fileContent[]", encoded)
	if c.config.ClientID != "" {
		form.Set("CLIENT_ID", c.config.ClientID)
	}

	c.rateMu.Lock()
	<-c.rateLimiter.C
	c.rateMu.Unlock()

	apiURL := c.buildAPIURL("disk.folder.uploadfile")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read upload response: %w", err)
	}

	var uploadResp struct {
		Result struct {
			ID int `json:"ID"`
		} `json:"result"`
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &uploadResp); err != nil {
		return "", fmt.Errorf("failed to parse upload response: %w", err)
	}
	if uploadResp.Error != "" {
		return "", fmt.Errorf("upload error: %s — %s", uploadResp.Error, uploadResp.Desc)
	}
	if uploadResp.Result.ID == 0 {
		return "", fmt.Errorf("upload returned no file ID")
	}

	// Step 3: Return [DISK=id] reference
	diskRef := fmt.Sprintf("[DISK=%d]", uploadResp.Result.ID)

	logger.InfoCF("bitrix24", "File uploaded", map[string]interface{}{
		"file":    fileName,
		"disk_id": uploadResp.Result.ID,
	})

	return diskRef, nil
}

// getChatFolderID returns the disk folder ID for a chat, caching the result.
func (c *Bitrix24Channel) getChatFolderID(ctx context.Context, chatID string) (string, error) {
	// Check cache
	if cached, ok := c.diskFolderCache.Load(chatID); ok {
		return cached.(string), nil
	}

	result, err := c.callAPI(ctx, "im.disk.folder.get", map[string]string{
		"CHAT_ID": chatID,
	})
	if err != nil {
		return "", err
	}

	var folder struct {
		ID int `json:"ID"`
	}
	if err := json.Unmarshal(result, &folder); err != nil {
		return "", fmt.Errorf("failed to parse folder response: %w", err)
	}
	if folder.ID == 0 {
		return "", fmt.Errorf("no folder ID for chat %s", chatID)
	}

	folderIDStr := fmt.Sprintf("%d", folder.ID)
	c.diskFolderCache.Store(chatID, folderIDStr)
	return folderIDStr, nil
}

// ============================================================================
// Markdown to BBCode (Issue #5)
// ============================================================================

var (
	reCodeBlock  = regexp.MustCompile("(?s)```[\\w]*\n?(.*?)```")
	reInlineCode = regexp.MustCompile("`([^`]+)`")
	reHeader     = regexp.MustCompile(`(?m)^#{1,6}\s+(.+)$`)
	reBold       = regexp.MustCompile(`\*\*(.+?)\*\*`)
	reBoldAlt    = regexp.MustCompile(`__(.+?)__`)
	reItalic     = regexp.MustCompile(`(?:^|\s)\*([^*\n]+)\*(?:\s|$)`)
	reStrike     = regexp.MustCompile(`~~(.+?)~~`)
	reLink       = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	reBlockquote = regexp.MustCompile(`(?m)^>\s?(.*)$`)
	reUnordList  = regexp.MustCompile(`(?m)^[\*\-]\s+(.+)$`)
	reHRule      = regexp.MustCompile(`(?m)^[-*]{3,}$`)
)

// markdownToBBCode converts Markdown to Bitrix24 BBCode.
// Bitrix24 supports: [B], [I], [U], [S], [URL=...], >> for quotes.
// Note: No [CODE] tag — code blocks are indented with tabs.
func markdownToBBCode(text string) string {
	result := text

	// Step 1: Extract code blocks and replace with placeholders
	var codeBlocks []string
	result = reCodeBlock.ReplaceAllStringFunc(result, func(match string) string {
		inner := reCodeBlock.FindStringSubmatch(match)
		if len(inner) > 1 {
			// Indent with tabs (Bitrix24 convention for code)
			trimmed := strings.TrimSpace(inner[1])
			lines := strings.Split(trimmed, "\n")
			indented := make([]string, len(lines))
			for i, line := range lines {
				indented[i] = "\t" + line
			}
			codeBlocks = append(codeBlocks, strings.Join(indented, "\n"))
		} else {
			codeBlocks = append(codeBlocks, match)
		}
		return fmt.Sprintf("\x00CODE%d\x00", len(codeBlocks)-1)
	})

	// Step 2: Extract inline code
	var inlineCode []string
	result = reInlineCode.ReplaceAllStringFunc(result, func(match string) string {
		inner := reInlineCode.FindStringSubmatch(match)
		if len(inner) > 1 {
			inlineCode = append(inlineCode, "[B]"+inner[1]+"[/B]")
		} else {
			inlineCode = append(inlineCode, match)
		}
		return fmt.Sprintf("\x00INLINE%d\x00", len(inlineCode)-1)
	})

	// Step 3: Convert headers to bold
	result = reHeader.ReplaceAllString(result, "[B]$1[/B]")

	// Step 4: Bold **text** and __text__
	result = reBold.ReplaceAllString(result, "[B]$1[/B]")
	result = reBoldAlt.ReplaceAllString(result, "[B]$1[/B]")

	// Step 5: Links [text](url)
	result = reLink.ReplaceAllString(result, "[URL=$2]$1[/URL]")

	// Step 6: Italic *text* (not at start of line to avoid list conflict)
	result = reItalic.ReplaceAllString(result, " [I]$1[/I] ")

	// Step 7: Strikethrough ~~text~~
	result = reStrike.ReplaceAllString(result, "[S]$1[/S]")

	// Step 8: Blockquotes > to >>
	result = reBlockquote.ReplaceAllString(result, ">>$1")

	// Step 9: Unordered lists
	result = reUnordList.ReplaceAllString(result, "• $1")

	// Step 10: Horizontal rules
	result = reHRule.ReplaceAllString(result, "────────────")

	// Step 11: Restore inline code
	for i, code := range inlineCode {
		result = strings.Replace(result, fmt.Sprintf("\x00INLINE%d\x00", i), code, 1)
	}

	// Step 12: Restore code blocks
	for i, code := range codeBlocks {
		result = strings.Replace(result, fmt.Sprintf("\x00CODE%d\x00", i), code, 1)
	}

	// Clean up extra blank lines
	result = regexp.MustCompile(`\n{3,}`).ReplaceAllString(result, "\n\n")

	return strings.Trim(result, "\n")
}

// ============================================================================
// Helpers
// ============================================================================

// webhookBaseURL returns the public base URL for webhook command registration.
func (c *Bitrix24Channel) webhookBaseURL() string {
	if c.config.WebhookBaseURL != "" {
		return strings.TrimRight(c.config.WebhookBaseURL, "/")
	}
	host := c.config.WebhookHost
	if host == "" || host == "0.0.0.0" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%d", host, c.config.WebhookPort)
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

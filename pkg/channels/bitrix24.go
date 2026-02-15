package channels

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/utils"
	"github.com/sipeed/picoclaw/pkg/voice"
)

// Bitrix24Channel implements the Channel interface for Bitrix24 CRM
// using HTTP webhook for receiving messages and REST API for sending.
type Bitrix24Channel struct {
	*BaseChannel
	config      config.Bitrix24Config
	httpServer  *http.Server
	httpClient  *http.Client
	rateLimiter *time.Ticker
	rateMu      sync.Mutex
	transcriber *voice.GroqTranscriber
	ctx         context.Context
	cancel      context.CancelFunc
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

// SetTranscriber sets the voice transcriber for audio message support.
func (c *Bitrix24Channel) SetTranscriber(t *voice.GroqTranscriber) {
	c.transcriber = t
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

	// Return 200 immediately, process asynchronously
	w.WriteHeader(http.StatusOK)

	// Parse the form-urlencoded body
	event := c.parseWebhookBody(string(body))

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
	if strings.TrimSpace(messageText) == "" {
		logger.DebugC("bitrix24", "Empty message, skipping")
		return
	}

	dialogID := firstNonEmpty(
		event.Params["DIALOG_ID"],
		event.Params["TO_CHAT_ID"],
		fromUserID,
	)

	userName := firstNonEmpty(event.User["NAME"], "User"+fromUserID)
	senderID := fromUserID

	metadata := map[string]string{
		"platform":   "bitrix24",
		"message_id": event.Params["MESSAGE_ID"],
		"user_name":  userName,
		"dialog_id":  dialogID,
	}

	logger.DebugCF("bitrix24", "Received message", map[string]interface{}{
		"sender_id": senderID,
		"dialog_id": dialogID,
		"preview":   utils.Truncate(messageText, 50),
	})

	// Send typing indicator (fire-and-forget)
	go c.sendTyping(dialogID)

	c.HandleMessage(senderID, dialogID, messageText, nil, metadata)
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
		webhookURL := fmt.Sprintf("https://%s:%d%s?secret=%s",
			c.config.WebhookHost,
			c.config.WebhookPort,
			c.config.WebhookPath,
			c.config.WebhookSecret,
		)
		if c.config.WebhookHost == "0.0.0.0" {
			// Use domain as fallback for public URL
			webhookURL = fmt.Sprintf("https://%s%s?secret=%s",
				c.config.Domain,
				c.config.WebhookPath,
				c.config.WebhookSecret,
			)
		}

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

// callAPI makes a rate-limited POST request to the Bitrix24 REST API.
func (c *Bitrix24Channel) callAPI(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	// Rate limiting: wait for ticker
	c.rateMu.Lock()
	<-c.rateLimiter.C
	c.rateMu.Unlock()

	apiURL := c.buildAPIURL(method)

	// Build form data
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	// Add CLIENT_ID (application_token) if configured
	if c.config.ClientID != "" {
		form.Set("CLIENT_ID", c.config.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitrix24 API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
		Desc   string          `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if apiResp.Error != "" {
		return nil, fmt.Errorf("bitrix24 API: %s — %s", apiResp.Error, apiResp.Desc)
	}

	return apiResp.Result, nil
}

// callAPIJSON makes a rate-limited POST with JSON body for complex parameters.
func (c *Bitrix24Channel) callAPIJSON(ctx context.Context, method string, payload interface{}) (json.RawMessage, error) {
	c.rateMu.Lock()
	<-c.rateLimiter.C
	c.rateMu.Unlock()

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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitrix24 API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
		Desc   string          `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if apiResp.Error != "" {
		return nil, fmt.Errorf("bitrix24 API: %s — %s", apiResp.Error, apiResp.Desc)
	}

	return apiResp.Result, nil
}

// Send sends a message to Bitrix24 via imbot.message.add.
func (c *Bitrix24Channel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("bitrix24 channel not running")
	}

	// Convert Markdown to BBCode
	formatted := markdownToBBCode(msg.Content)

	// Split long messages if needed (Bitrix24 limit ~60K chars)
	fragments := splitMessage(formatted, 60000)

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
func (c *Bitrix24Channel) sendTyping(dialogID string) {
	params := map[string]string{
		"DIALOG_ID": dialogID,
	}
	if c.config.BotID != "" {
		params["BOT_ID"] = c.config.BotID
	}

	_, err := c.callAPI(c.ctx, "imbot.chat.sendTyping", params)
	if err != nil {
		logger.DebugCF("bitrix24", "Failed to send typing indicator", map[string]interface{}{
			"error": err.Error(),
		})
	}
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

	return strings.TrimSpace(result)
}

// ============================================================================
// Message Splitting (Issue #14)
// ============================================================================

// splitMessage splits text at natural boundaries if it exceeds maxLen.
func splitMessage(text string, maxLen int) []string {
	if len(text) <= maxLen {
		return []string{text}
	}

	var fragments []string
	remaining := text

	for len(remaining) > maxLen {
		// Try to split at paragraph boundary
		cutPoint := findCutPoint(remaining, maxLen)
		fragments = append(fragments, strings.TrimSpace(remaining[:cutPoint]))
		remaining = strings.TrimSpace(remaining[cutPoint:])
	}

	if remaining != "" {
		fragments = append(fragments, remaining)
	}

	return fragments
}

// findCutPoint finds the best position to split text at or before maxLen.
func findCutPoint(text string, maxLen int) int {
	chunk := text[:maxLen]

	// Try double newline (paragraph break)
	if idx := strings.LastIndex(chunk, "\n\n"); idx > maxLen/2 {
		return idx + 2
	}

	// Try single newline
	if idx := strings.LastIndex(chunk, "\n"); idx > maxLen/2 {
		return idx + 1
	}

	// Fall back to maxLen
	return maxLen
}

// ============================================================================
// Helpers
// ============================================================================

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

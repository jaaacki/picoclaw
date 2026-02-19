package channels

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
)

// ============================================================================
// Config & Constructor Tests (Issue #1)
// ============================================================================

func TestBitrix24ConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Channels.Bitrix24.Enabled {
		t.Error("Bitrix24 should be disabled by default")
	}
	if cfg.Channels.Bitrix24.WebhookHost != "0.0.0.0" {
		t.Errorf("expected webhook_host 0.0.0.0, got %s", cfg.Channels.Bitrix24.WebhookHost)
	}
	if cfg.Channels.Bitrix24.WebhookPort != 18792 {
		t.Errorf("expected webhook_port 18792, got %d", cfg.Channels.Bitrix24.WebhookPort)
	}
	if cfg.Channels.Bitrix24.WebhookPath != "/webhook/bitrix24" {
		t.Errorf("expected webhook_path /webhook/bitrix24, got %s", cfg.Channels.Bitrix24.WebhookPath)
	}
}

func TestNewBitrix24Channel_RequiredFields(t *testing.T) {
	msgBus := bus.NewMessageBus()

	tests := []struct {
		name    string
		cfg     config.Bitrix24Config
		wantErr string
	}{
		{
			name:    "missing domain",
			cfg:     config.Bitrix24Config{Domain: "", WebhookSecret: "secret", BotID: "123"},
			wantErr: "domain is required",
		},
		{
			name:    "missing webhook_secret",
			cfg:     config.Bitrix24Config{Domain: "example.bitrix24.com", WebhookSecret: "", BotID: "123"},
			wantErr: "webhook_secret is required",
		},
		{
			name:    "missing bot_id",
			cfg:     config.Bitrix24Config{Domain: "example.bitrix24.com", WebhookSecret: "secret", BotID: ""},
			wantErr: "bot_id is required",
		},
		{
			name: "valid config",
			cfg: config.Bitrix24Config{
				Domain:        "example.bitrix24.com",
				WebhookSecret: "secret",
				BotID:         "123",
				WebhookHost:   "0.0.0.0",
				WebhookPort:   18792,
				WebhookPath:   "/webhook/bitrix24",
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := NewBitrix24Channel(tt.cfg, msgBus)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ch == nil {
					t.Error("expected channel, got nil")
				}
				if ch != nil && ch.Name() != "bitrix24" {
					t.Errorf("expected name bitrix24, got %s", ch.Name())
				}
			}
		})
	}
}

// ============================================================================
// Lifecycle Tests (Issue #2)
// ============================================================================

func TestBitrix24Channel_StartStop(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, err := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
		WebhookHost:   "127.0.0.1",
		WebhookPort:   0, // OS picks a port
		WebhookPath:   "/webhook/bitrix24",
	}, msgBus)
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}

	ctx := context.Background()

	if err := ch.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !ch.IsRunning() {
		t.Error("channel should be running after Start")
	}

	// Give server time to bind
	time.Sleep(50 * time.Millisecond)

	if err := ch.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if ch.IsRunning() {
		t.Error("channel should not be running after Stop")
	}
}

// ============================================================================
// Webhook Parsing Tests (Issue #3)
// ============================================================================

func TestParseWebhookBody_MessageEvent(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
	}, msgBus)

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=42&data[PARAMS][MESSAGE]=Hello+World&data[PARAMS][DIALOG_ID]=42&data[PARAMS][MESSAGE_ID]=999&data[USER][ID]=42&data[USER][NAME]=John&auth[application_token]=abc123"

	event := ch.parseWebhookBody(body)

	if event.Event != "ONIMMESSAGEADD" {
		t.Errorf("expected event ONIMMESSAGEADD, got %s", event.Event)
	}
	if event.Params["FROM_USER_ID"] != "42" {
		t.Errorf("expected FROM_USER_ID 42, got %s", event.Params["FROM_USER_ID"])
	}
	if event.Params["MESSAGE"] != "Hello World" {
		t.Errorf("expected MESSAGE 'Hello World', got %s", event.Params["MESSAGE"])
	}
	if event.Params["DIALOG_ID"] != "42" {
		t.Errorf("expected DIALOG_ID 42, got %s", event.Params["DIALOG_ID"])
	}
	if event.User["NAME"] != "John" {
		t.Errorf("expected USER NAME 'John', got %s", event.User["NAME"])
	}
	if event.Auth["application_token"] != "abc123" {
		t.Errorf("expected auth token 'abc123', got %s", event.Auth["application_token"])
	}
}

func TestParseWebhookBody_CommandEvent(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
	}, msgBus)

	body := "event=ONIMCOMMANDADD&data[COMMAND][0][COMMAND]=help&data[COMMAND][0][COMMAND_PARAMS]=all&data[COMMAND][0][USER_ID]=42&data[COMMAND][0][DIALOG_ID]=42&data[COMMAND][0][MESSAGE_ID]=100"

	event := ch.parseWebhookBody(body)

	if event.Event != "ONIMCOMMANDADD" {
		t.Errorf("expected event ONIMCOMMANDADD, got %s", event.Event)
	}
	if event.Params["CMD_COMMAND"] != "help" {
		t.Errorf("expected CMD_COMMAND 'help', got %s", event.Params["CMD_COMMAND"])
	}
	if event.Params["CMD_COMMAND_PARAMS"] != "all" {
		t.Errorf("expected CMD_COMMAND_PARAMS 'all', got %s", event.Params["CMD_COMMAND_PARAMS"])
	}
}

func TestParseWebhookBody_BotData(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
	}, msgBus)

	body := "event=ONIMMESSAGEADD&data[BOT][130387][BOT_ID]=130387&data[BOT][130387][TYPE]=B&data[PARAMS][FROM_USER_ID]=42&data[PARAMS][MESSAGE]=test"

	event := ch.parseWebhookBody(body)

	if event.Bot["BOT_ID"] != "130387" {
		t.Errorf("expected BOT_ID '130387', got %s", event.Bot["BOT_ID"])
	}
}

// ============================================================================
// Secret Verification Tests (Issue #3)
// ============================================================================

func TestVerifySecret(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "my-secret-token",
		BotID:         "1",
	}, msgBus)

	tests := []struct {
		name   string
		secret string
		want   bool
	}{
		{"valid secret", "my-secret-token", true},
		{"invalid secret", "wrong-token", false},
		{"empty secret", "", false},
		{"partial match", "my-secret", false},
		{"longer secret", "my-secret-token-extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ch.verifySecret(tt.secret); got != tt.want {
				t.Errorf("verifySecret(%q) = %v, want %v", tt.secret, got, tt.want)
			}
		})
	}
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
	}, msgBus)

	req := httptest.NewRequest(http.MethodGet, "/webhook/bitrix24", nil)
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestWebhookHandler_InvalidSecret(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "real-secret",
		BotID:         "1",
	}, msgBus)

	body := "event=ONIMMESSAGEADD&data[PARAMS][MESSAGE]=test"
	req := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=wrong", strings.NewReader(body))
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestWebhookHandler_ValidRequest(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "real-secret",
		BotID:         "1",
	}, msgBus)

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=42&data[PARAMS][MESSAGE]=Hello"
	req := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=real-secret", strings.NewReader(body))
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// ============================================================================
// REST API URL Tests (Issue #4)
// ============================================================================

func TestBuildAPIURL(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "company.bitrix24.com",
		WebhookSecret: "abc123secret",
		BotID:         "42",
		UserID:        "1",
		ClientID:      "app_token_xyz",
	}, msgBus)

	url := ch.buildAPIURL("imbot.message.add")
	expected := "https://company.bitrix24.com/rest/1/abc123secret/imbot.message.add"

	if url != expected {
		t.Errorf("expected URL:\n  %s\ngot:\n  %s", expected, url)
	}
}

// ============================================================================
// BBCode Conversion Tests (Issue #5)
// ============================================================================

func TestMarkdownToBBCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "bold",
			input:    "**hello**",
			expected: "[B]hello[/B]",
		},
		{
			name:     "bold alt",
			input:    "__hello__",
			expected: "[B]hello[/B]",
		},
		{
			name:     "strikethrough",
			input:    "~~deleted~~",
			expected: "[S]deleted[/S]",
		},
		{
			name:     "link",
			input:    "[Google](https://google.com)",
			expected: "[URL=https://google.com]Google[/URL]",
		},
		{
			name:     "header to bold",
			input:    "# Main Title",
			expected: "[B]Main Title[/B]",
		},
		{
			name:     "h2 to bold",
			input:    "## Section",
			expected: "[B]Section[/B]",
		},
		{
			name:     "blockquote",
			input:    "> quoted text",
			expected: ">>quoted text",
		},
		{
			name:     "unordered list dash",
			input:    "- item one\n- item two",
			expected: "• item one\n• item two",
		},
		{
			name:     "unordered list star",
			input:    "* item one\n* item two",
			expected: "• item one\n• item two",
		},
		{
			name:     "code block to indented",
			input:    "```go\nfmt.Println(\"hello\")\n```",
			expected: "\tfmt.Println(\"hello\")",
		},
		{
			name:     "inline code to bold",
			input:    "use `fmt.Println` here",
			expected: "use [B]fmt.Println[/B] here",
		},
		{
			name:     "horizontal rule",
			input:    "---",
			expected: "────────────",
		},
		{
			name:     "plain text unchanged",
			input:    "Just regular text",
			expected: "Just regular text",
		},
		{
			name:     "code block preserves inner markdown",
			input:    "```\n**not bold** in code\n```",
			expected: "\t**not bold** in code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := markdownToBBCode(tt.input)
			if got != tt.expected {
				t.Errorf("markdownToBBCode(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Message Splitting Tests (Issue #14) — moved to pkg/utils/message_test.go
// splitBitrix24Message was removed; callers now use utils.SplitMessage.
// ============================================================================

// ============================================================================
// DiskFolderCache Per-Instance Test
// ============================================================================

func TestBitrix24_DiskFolderCache_PerInstance(t *testing.T) {
	msgBus := bus.NewMessageBus()
	cfg := config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "test-secret",
		BotID:         "1",
	}

	ch1, err := NewBitrix24Channel(cfg, msgBus)
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := NewBitrix24Channel(cfg, msgBus)
	if err != nil {
		t.Fatal(err)
	}

	ch1.diskFolderCache.Store("chat123", "folder-A")

	if _, ok := ch2.diskFolderCache.Load("chat123"); ok {
		t.Error("ch2 should not see ch1's diskFolderCache entry — cache is not per-instance")
	}
}

// ============================================================================
// Group Chat Tests
// ============================================================================

func TestBitrix24_GroupChat_IgnoredWithoutMention(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:         "test.bitrix24.com",
		WebhookSecret:  "secret",
		BotID:          "42",
		GroupRespondAll: false,
	}, msgBus)
	ch.ctx, ch.cancel = context.WithCancel(context.Background())
	defer ch.cancel()

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=99&data[PARAMS][MESSAGE]=Hello+everyone&data[PARAMS][DIALOG_ID]=chat:100&data[PARAMS][MESSAGE_ID]=501"
	req := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=secret", strings.NewReader(body))
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// The bus should be empty — the message had no bot mention
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	msg, ok := msgBus.ConsumeInbound(ctx)
	if ok {
		t.Errorf("expected no message on bus, got: %+v", msg)
	}
}

func TestBitrix24_GroupChat_ProcessedWithMention(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:         "test.bitrix24.com",
		WebhookSecret:  "secret",
		BotID:          "42",
		GroupRespondAll: false,
	}, msgBus)
	ch.ctx, ch.cancel = context.WithCancel(context.Background())
	defer ch.cancel()

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=99&data[PARAMS][MESSAGE]=%5BUSER%3D42%5DBot+Name%5B%2FUSER%5D+Help+me&data[PARAMS][DIALOG_ID]=chat:100&data[PARAMS][MESSAGE_ID]=502"
	req := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=secret", strings.NewReader(body))
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	msg, ok := msgBus.ConsumeInbound(ctx)
	if !ok {
		t.Fatal("expected an InboundMessage on bus, got none")
	}
	if msg.ChatID != "chat:100" {
		t.Errorf("expected chat_id chat:100, got %s", msg.ChatID)
	}
}

func TestBitrix24_GroupChat_RespondAll(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:         "test.bitrix24.com",
		WebhookSecret:  "secret",
		BotID:          "42",
		GroupRespondAll: true,
	}, msgBus)
	ch.ctx, ch.cancel = context.WithCancel(context.Background())
	defer ch.cancel()

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=99&data[PARAMS][MESSAGE]=No+mention+here&data[PARAMS][DIALOG_ID]=chat:200&data[PARAMS][MESSAGE_ID]=503"
	req := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=secret", strings.NewReader(body))
	w := httptest.NewRecorder()

	ch.webhookHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	msg, ok := msgBus.ConsumeInbound(ctx)
	if !ok {
		t.Fatal("expected an InboundMessage on bus, got none")
	}
	if msg.ChatID != "chat:200" {
		t.Errorf("expected chat_id chat:200, got %s", msg.ChatID)
	}
}

// ============================================================================
// Event Deduplication Test
// ============================================================================

func TestBitrix24_EventDeduplication(t *testing.T) {
	msgBus := bus.NewMessageBus()
	ch, _ := NewBitrix24Channel(config.Bitrix24Config{
		Domain:        "test.bitrix24.com",
		WebhookSecret: "secret",
		BotID:         "1",
	}, msgBus)
	ch.ctx, ch.cancel = context.WithCancel(context.Background())
	defer ch.cancel()

	body := "event=ONIMMESSAGEADD&data[PARAMS][FROM_USER_ID]=42&data[PARAMS][MESSAGE]=Duplicate+test&data[PARAMS][DIALOG_ID]=42&data[PARAMS][MESSAGE_ID]=999"

	// First request
	req1 := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=secret", strings.NewReader(body))
	w1 := httptest.NewRecorder()
	ch.webhookHandler(w1, req1)

	// Second request (same event+message_id)
	req2 := httptest.NewRequest(http.MethodPost, "/webhook/bitrix24?secret=secret", strings.NewReader(body))
	w2 := httptest.NewRecorder()
	ch.webhookHandler(w2, req2)

	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Errorf("expected both requests to return 200, got %d and %d", w1.Code, w2.Code)
	}

	// Consume the first (expected) message
	ctx1, cancel1 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel1()
	_, ok := msgBus.ConsumeInbound(ctx1)
	if !ok {
		t.Fatal("expected at least 1 InboundMessage, got none")
	}

	// Verify no second message arrives (duplicate should have been dropped)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	msg, ok := msgBus.ConsumeInbound(ctx2)
	if ok {
		t.Errorf("expected no second message (duplicate), but got: %+v", msg)
	}
}

// ============================================================================
// WebhookBaseURL Test
// ============================================================================

func TestBitrix24_WebhookBaseURL(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		port   int
		base   string
		expect string
	}{
		{"explicit URL", "", 0, "https://picoclaw.example.com", "https://picoclaw.example.com"},
		{"trailing slash stripped", "", 0, "https://picoclaw.example.com/", "https://picoclaw.example.com"},
		{"host+port fallback", "192.168.1.1", 8080, "", "http://192.168.1.1:8080"},
		{"0.0.0.0 becomes localhost", "0.0.0.0", 8080, "", "http://localhost:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &Bitrix24Channel{
				config: config.Bitrix24Config{
					WebhookHost:    tt.host,
					WebhookPort:    tt.port,
					WebhookBaseURL: tt.base,
				},
			}
			if got := ch.webhookBaseURL(); got != tt.expect {
				t.Errorf("got %q, want %q", got, tt.expect)
			}
		})
	}
}


// ============================================================================
// Helper Tests
// ============================================================================

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "third"); got != "third" {
		t.Errorf("expected 'third', got %q", got)
	}
	if got := firstNonEmpty("first", "second"); got != "first" {
		t.Errorf("expected 'first', got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ============================================================================
// File Categorization Tests (Issue #10)
// ============================================================================

func TestCategorizeFile(t *testing.T) {
	tests := []struct {
		mimeType string
		filename string
		want     string
	}{
		{"image/jpeg", "photo.jpg", "image"},
		{"image/png", "screenshot.png", "image"},
		{"audio/mpeg", "voice.mp3", "voice"},
		{"audio/ogg", "memo.ogg", "voice"},
		{"video/mp4", "clip.mp4", "video"},
		{"application/pdf", "doc.pdf", "document"},
		{"application/msword", "file.doc", "document"},
		{"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "file.docx", "document"},
		{"application/octet-stream", "data.bin", "file"},
		// Extension fallback
		{"", "photo.jpg", "image"},
		{"", "voice.ogg", "voice"},
		{"", "clip.mp4", "video"},
		{"", "report.pdf", "document"},
		{"", "unknown.xyz", "file"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := categorizeFile(tt.mimeType, tt.filename)
			if got != tt.want {
				t.Errorf("categorizeFile(%q, %q) = %q, want %q", tt.mimeType, tt.filename, got, tt.want)
			}
		})
	}
}

func TestExtractBracketField(t *testing.T) {
	tests := []struct {
		key    string
		prefix string
		want   string
	}{
		{"data[PARAMS][MESSAGE]", "data[PARAMS][", "MESSAGE"},
		{"data[USER][NAME]", "data[USER][", "NAME"},
		{"auth[application_token]", "auth[", "application_token"},
	}

	for _, tt := range tests {
		got := extractBracketField(tt.key, tt.prefix)
		if got != tt.want {
			t.Errorf("extractBracketField(%q, %q) = %q, want %q", tt.key, tt.prefix, got, tt.want)
		}
	}
}

func TestExtractNestedBracketField(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"data[BOT][130387][BOT_ID]", "BOT_ID"},
		{"data[COMMAND][0][COMMAND]", "COMMAND"},
		{"data[COMMAND][0][COMMAND_PARAMS]", "COMMAND_PARAMS"},
	}

	for _, tt := range tests {
		got := extractNestedBracketField(tt.key)
		if got != tt.want {
			t.Errorf("extractNestedBracketField(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

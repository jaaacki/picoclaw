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
// Message Splitting Tests (Issue #14)
// ============================================================================

func TestSplitMessage(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		maxLen    int
		wantCount int
	}{
		{
			name:      "short message",
			text:      "hello",
			maxLen:    100,
			wantCount: 1,
		},
		{
			name:      "exact boundary",
			text:      "hello",
			maxLen:    5,
			wantCount: 1,
		},
		{
			name:      "split at paragraph",
			text:      "first paragraph\n\nsecond paragraph that makes it too long",
			maxLen:    25,
			wantCount: 2,
		},
		{
			name:      "split at newline",
			text:      "line one\nline two that is quite long",
			maxLen:    15,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fragments := splitBitrix24Message(tt.text, tt.maxLen)
			if len(fragments) != tt.wantCount {
				t.Errorf("splitMessage: got %d fragments, want %d", len(fragments), tt.wantCount)
				for i, f := range fragments {
					t.Logf("  fragment[%d] = %q", i, f)
				}
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

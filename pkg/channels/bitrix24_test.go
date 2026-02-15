package channels

import (
	"testing"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
)

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
				} else if !contains(err.Error(), tt.wantErr) {
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

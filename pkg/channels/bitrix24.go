package channels

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
)

// Bitrix24Channel implements the Channel interface for Bitrix24 CRM
// using HTTP webhook for receiving messages and REST API for sending.
type Bitrix24Channel struct {
	*BaseChannel
	config     config.Bitrix24Config
	httpServer *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
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

	c.setRunning(true)
	logger.InfoC("bitrix24", "Bitrix24 channel started (Webhook Mode)")
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (c *Bitrix24Channel) Stop(ctx context.Context) error {
	logger.InfoC("bitrix24", "Stopping Bitrix24 channel")

	if c.cancel != nil {
		c.cancel()
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

// Send sends a message to Bitrix24 (stub — implemented in Issue #4).
func (c *Bitrix24Channel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("bitrix24 channel not running")
	}
	logger.WarnC("bitrix24", "Send not yet implemented")
	return nil
}

// webhookHandler handles incoming Bitrix24 webhook requests (stub — implemented in Issue #3).
func (c *Bitrix24Channel) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

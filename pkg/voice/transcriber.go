package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/utils"
)

// TranscriptionResponse holds the result from any OpenAI-compatible transcription API.
type TranscriptionResponse struct {
	Text     string  `json:"text"`
	Language string  `json:"language,omitempty"`
	Duration float64 `json:"duration,omitempty"`
}

// Transcriber provides speech-to-text via any OpenAI-compatible /audio/transcriptions endpoint.
// Works with Groq, Qwen3-ASR, OpenAI Whisper, and any other compatible service.
type Transcriber struct {
	apiBase    string // e.g., "http://192.168.2.198:8100/v1" or "https://api.groq.com/openai/v1"
	apiKey     string // optional, blank = no Authorization header
	model      string // optional, e.g., "whisper-large-v3" or "qwen3-asr"
	httpClient *http.Client
}

// NewTranscriber creates a generic OpenAI-compatible speech-to-text transcriber.
// apiBase: base URL with /v1 (e.g., "http://192.168.2.198:8100/v1")
// apiKey: optional, leave blank for no auth (LAN services)
// model: optional, leave blank to omit from request (server uses its default)
func NewTranscriber(apiBase, apiKey, model string) *Transcriber {
	logger.DebugCF("voice", "Creating transcriber", map[string]interface{}{
		"api_base":  apiBase,
		"has_key":   apiKey != "",
		"model":     model,
	})

	return &Transcriber{
		apiBase: apiBase,
		apiKey:  apiKey,
		model:   model,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Transcribe sends an audio file to the transcription API.
func (t *Transcriber) Transcribe(ctx context.Context, audioFilePath string) (*TranscriptionResponse, error) {
	logger.InfoCF("voice", "Starting transcription", map[string]interface{}{"audio_file": audioFilePath})

	audioFile, err := os.Open(audioFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audio file: %w", err)
	}
	defer audioFile.Close()

	fileInfo, err := audioFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	logger.DebugCF("voice", "Audio file details", map[string]interface{}{
		"size_bytes": fileInfo.Size(),
		"file_name":  filepath.Base(audioFilePath),
	})

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	part, err := writer.CreateFormFile("file", filepath.Base(audioFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, audioFile); err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	if t.model != "" {
		if err := writer.WriteField("model", t.model); err != nil {
			return nil, fmt.Errorf("failed to write model field: %w", err)
		}
	}

	if err := writer.WriteField("response_format", "json"); err != nil {
		return nil, fmt.Errorf("failed to write response_format field: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	url := t.apiBase + "/audio/transcriptions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, &requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if t.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.apiKey)
	}

	logger.DebugCF("voice", "Sending transcription request", map[string]interface{}{
		"url":          url,
		"request_size": requestBody.Len(),
	})

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transcription API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result TranscriptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	logger.InfoCF("voice", "Transcription completed", map[string]interface{}{
		"text_length": len(result.Text),
		"language":    result.Language,
		"duration":    result.Duration,
		"preview":     utils.Truncate(result.Text, 50),
	})

	return &result, nil
}

// IsAvailable checks if the transcription service is reachable.
func (t *Transcriber) IsAvailable() bool {
	if t.apiBase == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try GET /models as a health check (works for most OpenAI-compatible APIs)
	req, err := http.NewRequestWithContext(ctx, "GET", t.apiBase+"/models", nil)
	if err != nil {
		return false
	}

	if t.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.apiKey)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		logger.DebugCF("voice", "Transcriber health check failed", map[string]interface{}{
			"api_base": t.apiBase,
			"error":    err.Error(),
		})
		return false
	}
	defer resp.Body.Close()

	available := resp.StatusCode == http.StatusOK
	logger.DebugCF("voice", "Transcriber health check", map[string]interface{}{
		"api_base":  t.apiBase,
		"available": available,
		"status":    resp.StatusCode,
	})
	return available
}

// GroqTranscriber is kept for backward compatibility with upstream.
// It creates a Transcriber pre-configured for Groq's API.
type GroqTranscriber = Transcriber

func NewGroqTranscriber(apiKey string) *GroqTranscriber {
	return NewTranscriber("https://api.groq.com/openai/v1", apiKey, "whisper-large-v3")
}

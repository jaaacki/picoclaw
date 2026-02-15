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

// QwenTranscriber implements speech-to-text using a Qwen3-ASR server
// via its OpenAI-compatible API endpoint.
type QwenTranscriber struct {
	apiBase    string // e.g., "http://192.168.2.198:8100/v1"
	model      string // e.g., "qwen3-asr"
	httpClient *http.Client
}

// NewQwenTranscriber creates a new Qwen3-ASR transcriber.
// apiBase should be the base URL including /v1 (e.g., "http://192.168.2.198:8100/v1").
func NewQwenTranscriber(apiBase string) *QwenTranscriber {
	logger.DebugCF("voice", "Creating Qwen3-ASR transcriber", map[string]interface{}{
		"api_base": apiBase,
	})

	return &QwenTranscriber{
		apiBase: apiBase,
		model:   "qwen3-asr",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Transcribe sends an audio file to the Qwen3-ASR server for transcription.
func (t *QwenTranscriber) Transcribe(ctx context.Context, audioFilePath string) (*TranscriptionResponse, error) {
	logger.InfoCF("voice", "Starting Qwen3-ASR transcription", map[string]interface{}{
		"audio_file": audioFilePath,
	})

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

	if err := writer.WriteField("model", t.model); err != nil {
		return nil, fmt.Errorf("failed to write model field: %w", err)
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

	logger.DebugCF("voice", "Sending transcription request to Qwen3-ASR", map[string]interface{}{
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
		return nil, fmt.Errorf("Qwen3-ASR API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result TranscriptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	logger.InfoCF("voice", "Qwen3-ASR transcription completed", map[string]interface{}{
		"text_length": len(result.Text),
		"language":    result.Language,
		"duration":    result.Duration,
		"preview":     utils.Truncate(result.Text, 50),
	})

	return &result, nil
}

// IsAvailable checks if the Qwen3-ASR server is reachable.
func (t *QwenTranscriber) IsAvailable() bool {
	if t.apiBase == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try a simple GET to the base URL to check connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", t.apiBase+"/models", nil)
	if err != nil {
		return false
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		logger.DebugCF("voice", "Qwen3-ASR health check failed", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}
	defer resp.Body.Close()

	available := resp.StatusCode == http.StatusOK
	logger.DebugCF("voice", "Qwen3-ASR health check", map[string]interface{}{
		"available": available,
		"status":    resp.StatusCode,
	})
	return available
}

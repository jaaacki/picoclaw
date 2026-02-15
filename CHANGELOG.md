# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

This changelog tracks the `jaaacki/picoclaw` fork. Upstream changes from `sipeed/picoclaw` are synced periodically.

## [0.2.0] — 2026-02-16

**Milestone: Bitrix24 Channel** — PicoClaw can now connect to Bitrix24 CRM as a chat channel, bringing AI agent capabilities to business teams already using Bitrix24 for CRM, project management, and internal communication. This is the first channel contributed from the fork and the first to support BBCode formatting, bot slash commands, and a 3-step file upload flow.

### Added
- Bitrix24 channel with full lifecycle management — config, HTTP webhook server, graceful shutdown (#1, #2)
- Webhook handler for `ONIMMESSAGEADD` events with form-urlencoded parsing and webhook secret verification via constant-time comparison (#3)
- REST API client for outbound messages via `imbot.message.add` with 1 req/sec rate limiter (#4)
- Markdown-to-BBCode conversion for Bitrix24 message formatting — bold, italic, code blocks (tab-indented), links, headers, quotes, lists (#5)
- Typing indicator via `imbot.chat.sendTyping` fired on every incoming message (#6)
- Bot slash command registration on startup via `imbot.command.register` with 409 conflict handling (#8)
- `ONIMCOMMANDADD` webhook routing — commands dispatched as `"/{command} {args}"` to the agent (#9)
- Incoming attachment download via `disk.file.get` with MIME-based categorization (image/audio/video/document) (#10)
- 3-step outbound file upload: `im.disk.folder.get` → `disk.folder.uploadfile` → `[DISK=id]` tag in message, with folder ID caching (#11)
- Voice message transcription for Bitrix24 using existing Groq Whisper transcriber (#12)
- Qwen3-ASR as alternative speech-to-text transcriber in `pkg/voice/qwen_transcriber.go` — connects to local GPU server via OpenAI-compatible API, with health check and Groq fallback (#13)
- Message length splitting at paragraph/code block boundaries for messages exceeding 60K characters (#14)
- `Bitrix24Config` with 11 fields, `Bitrix24Command` struct, `QwenASRConfig`, `VoiceConfig` in `pkg/config/config.go`
- Comprehensive test suite in `pkg/channels/bitrix24_test.go` — config defaults, constructor validation, webhook parsing, secret verification, HTTP handler, API URL construction, BBCode conversion, message splitting, file categorization
- Environment variable support: `PICOCLAW_CHANNELS_BITRIX24_*` and `PICOCLAW_VOICE_QWEN_ASR_*` in `.env.example`
- Living documentation: CHANGELOG.md, ROADMAP.md, LEARNING_LOG.md (#7, #15)
- README.md: Bitrix24 setup guide, config examples, voice/ASR configuration (#7)

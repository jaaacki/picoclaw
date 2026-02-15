# OpenClaw vs PicoClaw Integration Analysis

## Existing OpenClaw Ecosystem (192.168.2.191:~/Dev)

### 1. OpenClaw Bitrix24 Connector (`openclaw-bitrix24`)

**Version:** 1.2.0 | **Language:** TypeScript | **Framework:** OpenClaw Plugin SDK

Full two-way messaging connector between OpenClaw and Bitrix24 CRM. Implements the OpenClaw `ChannelPlugin` interface.

**Message Flow:**
```
Outbound: Agent -> OpenClaw -> Bitrix24Client -> Bitrix24 REST API -> User
Inbound:  User -> Bitrix24 -> Webhook POST -> /chan/bitrix24/webhook -> OpenClaw -> Agent
```

**Key Files:**

| File | Purpose |
|------|---------|
| `index.ts` | Plugin entry point — registers with OpenClaw via `register(api)` |
| `src/channel.ts` | Implements `ChannelPlugin<ResolvedBitrix24Account>` — full channel interface |
| `src/client.ts` | `Bitrix24Client` — REST API client with rate limiting (1 req/sec), Markdown→BBCode, bot commands, file upload, typing indicators |
| `src/webhook.ts` | ~1,967 lines — handles `ONIMMESSAGEADD` and `ONIMCOMMANDADD`. Full attachment pipeline: file download, image analysis, PDF extraction, voice transcription |
| `src/config.ts` | Zod schemas for config validation |
| `src/accounts.ts` | Multi-account resolution — default + named accounts |
| `src/runtime.ts` | Dependency injection — stores OpenClaw `PluginRuntime` |
| `src/types.ts` | Type definitions for attachments, file info, typing, commands |

**Capabilities:**
- Two-way messaging via webhooks + REST API
- Markdown ↔ BBCode conversion (Bitrix24 uses BBCode)
- Bot commands — register, update, unregister, show/hide, bulk update via `imbot.command` API
- File attachments — 3-step upload flow (`im.disk.folder.get` → `disk.folder.uploadfile` → `imbot.message.add` with `[DISK=id]`)
- Voice transcription — configurable ASR (`auto`/`qwen`/`openai`). Auto checks Qwen3-ASR reachability, falls back to OpenAI Whisper. MP3→WAV via ffmpeg.
- Image analysis — saves to temp, uses OpenClaw image tools
- PDF processing — text extraction (Tj/TJ operators), embedded JPEG extraction from scanned PDFs
- Security — `crypto.timingSafeEqual` for webhook secret verification
- Typing indicators — `imbot.chat.sendTyping` sent immediately on receive
- Timeout protection — 5min agent dispatch, 3min commands
- Multi-domain support with named accounts
- `MEDIA:` token handling for audio/file delivery
- Custom command registration on startup

**Config:** Under `channels.bitrix24` in `openclaw.json` — `domain`, `webhookSecret`, `userId`, `botId`, `clientId`, `dmPolicy`, `accounts`, `customCommands`, `registerCommandsOnStartup`, `webhookUrl`, `asrProvider`, `qwenAsrUrl`

---

### 2. OpenClaw Qwen3-ASR Plugin (`openclaw-qwen3-asr`)

**Version:** 1.0.0 | **Language:** TypeScript

STT plugin connecting to GPU-accelerated Qwen3-ASR server at `192.168.2.198:8100` via OpenAI-compatible API.

- 3-file plugin: `types.ts`, `client.ts`, `index.ts`
- Registers `qwen_asr` agent tool — accepts audio file path, returns transcription
- Health check with 30s TTL cache
- Retry with exponential backoff on 5xx
- Zero runtime deps (native `fetch`, `FormData`, `File`)
- Formats: WAV, MP3, FLAC, OGG, MP4, M4A, WebM
- Languages: Japanese, English, Chinese, auto-detect

---

### 3. OpenClaw Qwen3-TTS Plugin (`openclaw-qwen3-tts`)

**Version:** 1.0.0 | **Language:** TypeScript

TTS plugin connecting to GPU-accelerated Qwen3-TTS server at `192.168.2.198:8101` via OpenAI-compatible API.

- 3-file plugin: `types.ts`, `client.ts`, `index.ts`
- Registers `qwen_tts` agent tool — generates audio from text
- Serves generated audio at `/chan/qwen3-tts/audio/`
- Saves to `~/.openclaw/media/tts/` with 5min auto-cleanup
- Returns `MEDIA: <url>` tokens for channel delivery
- 9 native voices: vivian, serena, uncle_fu, dylan, eric, ryan, aiden, ono_anna, sohee (+ 6 OpenAI aliases)
- Formats: WAV, MP3, FLAC, OGG
- Instruct mode for tone/emotion control
- Health check with 30s TTL cache

---

### 4. OpenClaw FreePBX Voice Call Integration (`openclaw-freepbx`)

**Version:** 0.4.5 (plugin) / 0.3.6 (asterisk-api) | **Language:** TypeScript

Two-component system for AI-powered voice calling:

**Component A: `asterisk-api/` — REST API Bridge**
Node.js service connecting to Asterisk 21 (Docker on Synology NAS at 192.168.2.198) via ARI:
- REST endpoints for call control (originate, answer, hang up, transfer, play, record, DTMF)
- Server-side TTS via Qwen3-TTS streamed to calls via ExternalMedia WebSocket
- Real-time ASR via Qwen3-ASR WebSocket — Snoop channel captures audio, bridges to ExternalMedia, streams PCM
- WebSocket event stream at `/events` for real-time call state
- Recording management, bridge/conferencing, allowlist with hot-reload
- Docker Compose deployment (dev + prod)

**Component B: `openclaw-voice-call/` — OpenClaw Plugin**
- `voice_call` agent tool (initiate, speak, listen, end)
- CLI commands under `voicecall` namespace
- Gateway RPC methods
- WebSocket event manager for call state tracking
- Conversation loop: transcription → agent → TTS → playback

**Full Pipeline:**
```
OpenClaw Agent → voice_call tool → plugin → asterisk-api REST → ARI → Asterisk → SIP trunk → PSTN
```

---

### 5. Claude Code Telegram Bot (`claude-code-telegram`)

**Language:** Python 3.10+ | **Framework:** python-telegram-bot

Telegram bot for remote Claude Code access:
- Agentic mode (default) + classic mode with 13 commands
- Claude Code SDK integration with CLI fallback
- Session persistence per user/project (SQLite)
- Webhook API for GitHub events, cron scheduler
- Security: whitelist, rate limiting, directory sandboxing, audit logging

---

### 6. Other Projects

| Project | Description |
|---------|-------------|
| `deepagents` | LangChain + Deep Agents workflow — GitHub issue analysis with Claude |
| `ci-cd-woodpecker` | Woodpecker CI pipelines with AI-powered auto-fix |
| `xero-integration` | PRD documents for Xero/ERP integration (planning phase) |
| `freepbx` | Asterisk/FreePBX config data volume for Docker instance |
| `research` | Bitrix24 JS SDK research document (23KB) |

---

## PicoClaw Channel Architecture

### Core Interface

All channels implement (`pkg/channels/base.go`):
```go
type Channel interface {
    Name() string
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Send(ctx context.Context, msg bus.OutboundMessage) error
    IsRunning() bool
    IsAllowed(senderID string) bool
}
```

### Message Types (`pkg/bus/types.go`)

```go
// Inbound (channel → agent)
type InboundMessage struct {
    Channel    string
    SenderID   string
    ChatID     string
    Content    string
    Media      []string
    SessionKey string            // "channel:chatID"
    Metadata   map[string]string
}

// Outbound (agent → channel)
type OutboundMessage struct {
    Channel string
    ChatID  string
    Content string
}
```

### Connection Patterns

**Webhook/HTTP (LINE, Slack, Feishu):** Channel starts own HTTP server, registers handler route, validates signatures.

**WebSocket/Polling (Telegram, DingTalk, WhatsApp):** Connects to external service, spawns listener goroutine.

### Registration (`pkg/channels/manager.go`)

Channels are initialized in `initChannels()` and stored in a map. Errors don't crash — logged and skipped.

---

## Comparison: OpenClaw vs PicoClaw

| Aspect | OpenClaw (TypeScript) | PicoClaw (Go) |
|--------|----------------------|---------------|
| Plugin system | `ChannelPlugin` SDK, `register(api)` | Direct Go interface, compiled in |
| Interface complexity | Complex (config, security, messaging, outbound, gateway, status) | Simple: 6 methods |
| Message bus | Plugin runtime dispatch | `bus.InboundMessage` / `bus.OutboundMessage` pub/sub |
| Config validation | Zod schemas, multi-account | JSON struct with `FlexibleStringSlice` allowlist |
| Webhook routing | OpenClaw gateway routes | Channel starts its own HTTP server |
| Dynamic loading | Yes — plugins loaded at runtime | No — compiled into binary |
| Media/attachment system | `MEDIA:` tokens, file upload pipelines | Basic `Media []string` paths only |
| TTS/ASR | Plugin-based (Qwen3-ASR, Qwen3-TTS) | Only Groq Whisper in `pkg/voice/` |
| Multi-account | Supported per channel | Not supported |

---

## Porting Effort: OpenClaw Features → PicoClaw

### Bitrix24 Channel

| Feature | Effort | Notes |
|---------|--------|-------|
| Webhook receive (`ONIMMESSAGEADD`) | Straightforward | Follow LINE channel pattern — HTTP server + signature verify |
| Send via REST API (`imbot.message.add`) | Straightforward | In `Send()` method, HTTP POST |
| Markdown → BBCode conversion | Medium | Port conversion logic from TS to Go |
| Bot command registration | Medium | Call `imbot.command.register` in `Start()` |
| File upload (3-step flow) | Medium | `im.disk.folder.get` → `disk.folder.uploadfile` → `[DISK=id]` |
| Typing indicators | Easy | Fire-and-forget HTTP call on receive |
| Webhook secret verification | Easy | HMAC-SHA256, same as LINE pattern |
| Multi-account support | Needs design | PicoClaw has no multi-account pattern |
| Rate limiting (1 req/sec) | Easy | `time.Ticker` or token bucket in Go |
| Voice transcription (ASR) | Separate | See STT/TTS section |
| PDF extraction / image analysis | Separate | Needs tool integration |
| Timeout protection | Easy | `context.WithTimeout` — native Go |
| `MEDIA:` token handling | Needs design | PicoClaw has no media token system |

**Estimated core channel:** ~500-700 lines of Go (webhook + send + BBCode + commands)

### Qwen3-ASR

**Option A:** Add `QwenTranscriber` in `pkg/voice/` alongside existing `GroqTranscriber` (~100-150 lines)
**Option B:** Register as `qwen_asr` tool in `pkg/tools/` (more flexible, less integrated)

### Qwen3-TTS

PicoClaw has no TTS. Requires:
- New `pkg/tts/` package
- HTTP client for `192.168.2.198:8101`
- Audio file serving endpoint
- `MEDIA:` token convention or equivalent
- ~200-300 lines of Go

### FreePBX Voice Calls

Most complex. The `asterisk-api` Node.js bridge stays as-is. PicoClaw side needs:
- New channel or tool calling asterisk-api REST
- WebSocket event stream for call state
- ASR→Agent→TTS loop through message bus
- Significant effort — port last

---

## Suggested Priority

1. **Bitrix24 channel** (core webhook + send) — basic connectivity
2. **Qwen3-ASR provider** — voice message transcription
3. **Qwen3-TTS + media delivery** — audio responses
4. **File attachments + BBCode** — enriched Bitrix experience
5. **Bot commands** — slash command registration
6. **FreePBX voice channel** — full telephony (biggest effort)

---

## Key Concerns

- **Language shift:** Entire OpenClaw ecosystem is TypeScript; PicoClaw is Go. No code reuse possible — everything must be rewritten.
- **Plugin model:** OpenClaw supports runtime plugins; PicoClaw requires compiling channels into the binary. Any changes require rebuilding.
- **Media system gap:** PicoClaw lacks the `MEDIA:` token convention and file serving infrastructure that the OpenClaw TTS/voice stack relies on.
- **Multi-account:** OpenClaw Bitrix connector supports multiple Bitrix domains. PicoClaw has no equivalent pattern.
- **Maturity:** OpenClaw connectors are battle-tested in production. PicoClaw just launched (Feb 9, 2026).

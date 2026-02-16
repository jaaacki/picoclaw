# Learning Log

Design decisions, patterns discovered, and lessons learned during development. Written for someone coming to this codebase fresh.

---

## #1 — Config structure follows PicoClaw conventions (Issue #1)

**Why this design:** PicoClaw uses a single nested `Config` struct in `pkg/config/config.go` with JSON tags and `env` tags for environment variable overrides. Every channel gets a sub-struct inside `ChannelsConfig`. We followed this exactly for Bitrix24 — adding `Bitrix24Config` with 11 fields matching the TypeScript reference implementation.

**What could go wrong:** The `AllowFrom` field uses `FlexibleStringSlice`, a custom type that accepts both `["123","456"]` JSON arrays and `123,456` comma-separated strings from env vars. If you forget this and use `[]string`, env var parsing will break silently.

---

## #2-4 — Porting a TypeScript SDK to bare HTTP calls (Issues #2, #3, #4)

**Why this design:** Bitrix24 has a JavaScript SDK, but it's just a thin wrapper over REST endpoints. Rather than finding or creating a Go SDK, we call the REST API directly with `net/http`. The URL pattern is `https://{domain}/rest/{userId}/{webhookSecret}/{method}` — note that `webhookSecret` goes in the URL path (not `clientId` as initially planned). This was a critical correction found by reading the TypeScript source.

**What just happened:** The reference TypeScript code uses `clientId` as a body parameter (`CLIENT_ID`), not a URL segment. The plan originally had the URL wrong. Lesson: always verify API patterns against working code, not documentation or memory.

**What could go wrong:** Bitrix24 enforces a strict 1 request/second rate limit. We use `time.Ticker` with a mutex — every API call waits for a tick before proceeding. If you bypass `callAPI()` and hit the API directly, you'll get throttled and eventually blocked.

---

## #3 — Webhook parsing is the trickiest part (Issue #3)

**Why this design:** Bitrix24 sends webhooks as `application/x-www-form-urlencoded` with bracket-notation nested keys like `data[PARAMS][MESSAGE]`, `data[BOT][130387][BOT_ID]`, and `auth[application_token]`. Go's `url.ParseQuery` doesn't understand bracket nesting, so we wrote `parseWebhookBody()` that extracts specific known fields using string matching on the raw query values.

**What just happened:** The TypeScript version builds a full nested object from the form data. In Go, we took a simpler approach — we only extract the fields we actually need. This is less general but more predictable and easier to test.

**What could go wrong:** The secret verification uses `auth[application_token]` from the POST body matched against the configured `WebhookSecret`. We use `crypto/subtle.ConstantTimeCompare` to prevent timing attacks. If you switch to simple `==` comparison, you introduce a timing side channel.

---

## #5 — Bitrix24 has no [CODE] BBCode tag (Issue #5)

**Why this design:** Bitrix24's BBCode renderer does not support `[CODE]` tags for code blocks, unlike forums. The TypeScript reference uses tab-indented lines as a workaround — each line of a code block gets a tab prefix, which Bitrix24 renders in a monospace-like style. We replicated this in `markdownToBBCode()`.

**What just happened:** Code blocks are extracted first (like `telegram.go` does for HTML) to protect their contents from other conversions. Inline backtick code uses `[B]` (bold) as a visual approximation since there's no inline code BBCode either.

---

## #8-9 — Bot commands register once, handle forever (Issues #8, #9)

**Why this design:** Bitrix24 bot commands are registered via `imbot.command.register` API call. Once registered, they persist server-side — you don't need to re-register every time. Our `Start()` method registers commands and handles 409 (already exists) gracefully. Commands arrive as `ONIMCOMMANDADD` webhook events, which we dispatch as `"/{command} {args}"` text to the agent.

**What could go wrong:** If you change a command's title or description, the old registration persists. There's no update-or-create API — you'd need to delete and re-register. We don't handle this yet; changing command metadata requires manual cleanup in Bitrix24.

---

## #10-12 — File handling requires 3 API calls to upload (Issues #10, #11, #12)

**Why this design:** Bitrix24's file upload flow is: (1) get the chat's disk folder ID via `im.disk.folder.get`, (2) upload the file to that folder via `disk.folder.uploadfile` (multipart), (3) reference it in the message with `[DISK=id]`. We cache the folder ID per dialog in a `sync.Map` to avoid repeated step-1 calls.

**What just happened:** Incoming attachments are simpler — `disk.file.get` returns a download URL. We categorize by MIME type first, falling back to file extension. Audio files trigger voice transcription if a transcriber is configured.

**What could go wrong:** Temp files from downloads must be cleaned up. We use `defer os.Remove()` immediately after creating them. If the process crashes between download and cleanup, temp files will accumulate. A production deployment should have periodic temp directory cleanup.

---

## #13 — Pluggable transcriber interface (Issue #13)

**Why this design:** The original PicoClaw hardcodes `GroqTranscriber` for voice-to-text. We introduced a `Transcriber` interface in `bitrix24.go` so the channel accepts any implementation. Two are available: Groq (cloud, needs API key) and Qwen3-ASR (local GPU at 192.168.2.198:8100, no API key needed). The wiring in `main.go` tries Qwen first (via health check) and falls back to Groq.

**What could go wrong:** The Qwen3-ASR health check (`GET /v1/models`) has a 5-second timeout. If the GPU server is slow to respond, the check may fail and fall back to Groq even when Qwen is technically available. This is acceptable for startup but could be improved with retry logic.

---

## Architecture pattern — How PicoClaw channels work

Every channel follows the same pattern (visible in `telegram.go`, `line.go`, `slack.go`):

1. Embed `BaseChannel` for common fields (config, bus, running state, logger)
2. Constructor validates required config, returns error if missing
3. `Start()` launches goroutines (long poll or HTTP server), sets `running = true`
4. `Stop()` signals shutdown, waits for goroutines, sets `running = false`
5. `Send()` formats and delivers messages to the platform
6. Incoming messages go through `HandleMessage()` on `BaseChannel` which publishes to the message bus

The message bus is a simple pub/sub — channels publish, the agent subscribes. This decoupling means adding a new channel requires zero changes to the agent code.

---

## #15 — Porting from TypeScript to Go: what worked (Issue #15)

**Why this design:** The entire Bitrix24 channel was ported from a ~3,864 LOC TypeScript implementation (OpenClaw) to ~700 LOC Go. The reduction isn't because Go is more concise — it's because we dropped the JavaScript SDK abstraction layer and called REST APIs directly with `net/http`. The TypeScript version used Zod schemas, class hierarchies, and async/await patterns that don't translate to Go idioms.

**What just happened:** The most valuable step was reading the actual TypeScript source code on the dev server before writing any Go. This caught the URL pattern error in the original plan (`clientId` vs `webhookSecret` in the URL path) and revealed undocumented Bitrix24 behaviors like the bracket-notation form encoding and the missing `[CODE]` BBCode tag.

**What could go wrong:** Without a local Go compiler (builds happen in Docker), we can't run `go test` locally. The test suite was written to be comprehensive so that the first Docker build catches issues. For future milestones, setting up Go locally or adding a CI pipeline would speed up the feedback loop.

---

## #16 — Upstream is a branch overlay, not a single folder (Issue #16)

**Why this design:** In a Git fork, upstream content is spread across the same repository tree; it is not physically grouped into an `upstream/` directory. To keep merge risk low, we defined explicit fork-owned zones (`fork/`, `docs/`, `scripts/`, `.github/workflows/fork-guard.yml`) and treated everything else as upstream-owned by default.

**What just happened:** We verified ownership directly against `upstream/main` with `git ls-tree`, which confirmed the root `README.md` is upstream-owned while the new governance files are fork-only. This gives us a concrete, auditable rule instead of relying on memory.

**What could go wrong:** If the allowlist is too strict, legitimate integration fixes may get blocked; if it is too loose, upstream files drift and future sync conflicts expand. The policy therefore includes explicit exception paths (baseline mode and review-visible override tags).

---

## #17 — Two-lane enforcement keeps velocity while reducing drift (Issue #17)

**Why this design:** A hard rule on day one can freeze progress in a fork that already diverged. We use three guard modes: `strict` for greenfield discipline, `baseline` for current divergence migration, and `sync` for reporting during upstream merges.

**What just happened:** The guard script and CI workflow were documented and validated with container compile checks. We also moved a merge-time helper-name fix into fork-owned Bitrix24 files to avoid touching `pkg/channels/discord.go` (upstream-owned).

**What could go wrong:** Baseline mode can become permanent technical debt if never tightened. The mitigation is to regularly shrink `fork/upstream_touch_baseline.txt` and promote checks from `baseline` to `strict` once integration fixes are isolated.

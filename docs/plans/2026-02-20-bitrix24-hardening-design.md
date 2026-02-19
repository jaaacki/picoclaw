# Bitrix24 Channel Hardening — Design

**Date:** 2026-02-20
**Branch:** `milestone/bitrix24-channel`
**Scope:** Hardening PR (Phase 1 of 2)

## Goal

Harden the Bitrix24 channel plugin (`pkg/channels/bitrix24.go`) for potential upstream PR
submission. Priority: correctness, code quality, group chat support, and upstream style
alignment. No new external dependencies.

---

## Changes

### 1. Move `diskFolderCache` into the struct

**File:** `pkg/channels/bitrix24.go`

Package-level `var diskFolderCache sync.Map` at line 764 causes cross-instance and cross-test
state bleed. Move it into `Bitrix24Channel` as an instance field.

**Struct change:**
```go
type Bitrix24Channel struct {
    *BaseChannel
    config          config.Bitrix24Config
    httpServer      *http.Server
    httpClient      *http.Client
    rateLimiter     *time.Ticker
    rateMu          sync.Mutex
    ctx             context.Context
    cancel          context.CancelFunc
    diskFolderCache sync.Map // chatID → folderID string (was package-level)
    seenEvents      sync.Map // eventKey → expiry time.Time (deduplication)
}
```

Remove the `var diskFolderCache sync.Map` package-level declaration.
Update all usages: `diskFolderCache.Load(...)` → `c.diskFolderCache.Load(...)` etc.

---

### 2. DRY: Extract `callAPIRaw`, slim down `callAPI` / `callAPIJSON`

**File:** `pkg/channels/bitrix24.go`

`callAPI` (line 596) and `callAPIJSON` (line 651) share ~80% identical code
(rate limit, HTTP POST, read body, check status, return `json.RawMessage`).
They differ only in how they encode the request body (form values vs JSON body).

**Approach:** Extract a private `callAPIRaw` that handles rate-limiting, HTTP execution,
response reading, and error checking. Both `callAPI` and `callAPIJSON` become thin wrappers
that build the request body and call `callAPIRaw`.

```go
// callAPIRaw executes a rate-limited POST to the Bitrix24 REST API.
// req must already have Content-Type set.
func (c *Bitrix24Channel) callAPIRaw(ctx context.Context, method string, req *http.Request) (json.RawMessage, error)

// callAPI remains public signature (map[string]string params → form-encoded body)
func (c *Bitrix24Channel) callAPI(ctx context.Context, method string, params map[string]string) (json.RawMessage, error)

// callAPIJSON remains public signature (interface{} payload → JSON body)
func (c *Bitrix24Channel) callAPIJSON(ctx context.Context, method string, payload interface{}) (json.RawMessage, error)
```

The rate-limit wait (`<-c.rateLimiter.C`) and `c.rateMu` locking moves exclusively into
`callAPIRaw`. `callAPI` and `callAPIJSON` only build the request body, then delegate.

---

### 3. Replace `splitBitrix24Message` with `utils.SplitMessage`

**File:** `pkg/channels/bitrix24.go`

The fork-local `splitBitrix24Message` (line 981) duplicates `utils.SplitMessage` which is
already in the upstream codebase and used by the Discord channel.

- Remove `splitBitrix24Message` entirely
- Replace callers: `splitBitrix24Message(formatted, 60000)` → `utils.SplitMessage(formatted, 60000)`
- `utils` is already imported

---

### 4. Event deduplication

**File:** `pkg/channels/bitrix24.go`

Bitrix24 can fire duplicate webhook events (network retries). Add simple TTL-based
deduplication keyed on `eventType:messageID`.

**Implementation:**
- Add `seenEvents sync.Map` to struct (value type: `time.Time` = expiry)
- In `webhookHandler` (or top of `processEvent`), before dispatching:
  ```go
  const dedupTTL = 5 * time.Minute
  key := eventType + ":" + messageID  // e.g. "ONIMBOTMESSAGEADD:12345"
  expiry := time.Now().Add(dedupTTL)
  if prev, loaded := c.seenEvents.LoadOrStore(key, expiry); loaded {
      if time.Now().Before(prev.(time.Time)) {
          return // duplicate
      }
      c.seenEvents.Store(key, expiry) // re-arm expired entry
  }
  ```
- Add a background cleanup goroutine in `Start()` that sweeps expired entries every minute:
  ```go
  go func() {
      ticker := time.NewTicker(time.Minute)
      defer ticker.Stop()
      for {
          select {
          case <-ticker.C:
              now := time.Now()
              c.seenEvents.Range(func(k, v interface{}) bool {
                  if now.After(v.(time.Time)) {
                      c.seenEvents.Delete(k)
                  }
                  return true
              })
          case <-c.ctx.Done():
              return
          }
      }
  }()
  ```
- The messageID to key on: for `ONIMBOTMESSAGEADD` use `PARAMS[MESSAGE_ID]`;
  for `ONIMBOTCOMMANDADD` use `PARAMS[COMMAND_ID]`. Fall back to full event body hash
  if neither is present.

---

### 5. `sendTyping` exempt from rate limiter

**File:** `pkg/channels/bitrix24.go`

`sendTyping` (line 743) currently calls `callAPI` which waits for the rate-limit token.
This competes with real message sends. Typing indicators are best-effort and should not
block or consume the shared rate-limit slot.

**Implementation:**
- Give `sendTyping` its own fire-and-forget HTTP call that bypasses `callAPIRaw`'s rate
  limiting. Build the form body and POST directly using `c.httpClient`.
- Already called in a goroutine (`go c.sendTyping(...)`) — make the body itself non-blocking.

---

### 6. Group chat support

**Files:** `pkg/config/config.go`, `pkg/channels/bitrix24.go`

Bitrix24 sends `ONIMBOTMESSAGEADD` for both DMs and group chats. The `DIALOG_ID` field
distinguishes them:
- `1:USER_ID` → direct message
- `chat:CHAT_ID` → group/open channel chat

#### Config additions (`pkg/config/config.go`)

Add two fields to `Bitrix24Config`:

```go
// GroupRespondAll controls bot response behavior in group chats.
// false (default): respond only when @mentioned.
// true: respond to every message in the group.
GroupRespondAll bool `json:"group_respond_all" env:"PICOCLAW_CHANNELS_BITRIX24_GROUP_RESPOND_ALL"`

// WebhookBaseURL is the public base URL for this bot's webhook endpoint.
// Used when registering bot commands. E.g. "https://picoclaw.example.com"
// Falls back to constructing from WebhookHost:WebhookPort if empty.
WebhookBaseURL string `json:"webhook_base_url" env:"PICOCLAW_CHANNELS_BITRIX24_WEBHOOK_BASE_URL"`
```

Add defaults in `DefaultConfig()`:
```go
GroupRespondAll: false,
WebhookBaseURL:  "",
```

#### Event routing (`pkg/channels/bitrix24.go`)

In the message event handler (around line 300), after extracting `DIALOG_ID`:

```go
isGroupChat := strings.HasPrefix(dialogID, "chat:")

if isGroupChat && !c.config.GroupRespondAll {
    // Only respond if the bot is @mentioned.
    // Bitrix24 mentions use BBCode: [USER=<botID>]Name[/USER]
    mentionTag := "[USER=" + c.config.BotID + "]"
    if !strings.Contains(messageText, mentionTag) {
        logger.DebugCF("bitrix24", "Ignoring group message (not mentioned)",
            map[string]interface{}{"dialog_id": dialogID})
        return
    }
}
```

For conversation routing in group chats, use `DIALOG_ID` directly as `ChatID` in the
`bus.InboundMessage` (already the case — confirm in processEvent). This ensures separate
conversation contexts per group chat vs per DM user.

#### `registerCommands` webhook URL fix

Replace the fragile `0.0.0.0` check with `WebhookBaseURL` when set:
```go
func (c *Bitrix24Channel) webhookBaseURL() string {
    if c.config.WebhookBaseURL != "" {
        return strings.TrimRight(c.config.WebhookBaseURL, "/")
    }
    host := c.config.WebhookHost
    if host == "" || host == "0.0.0.0" {
        host = "localhost"
    }
    return fmt.Sprintf("http://%s:%d", host, c.config.WebhookPort)
}
```

---

## Tests to add/update

**File:** `pkg/channels/bitrix24_test.go`

- `TestBitrix24Channel_DiskFolderCache_PerInstance` — confirm two channel instances have
  independent caches (store in A, not visible in B)
- `TestBitrix24Channel_EventDeduplication` — simulate duplicate webhook event, confirm only
  processed once
- `TestBitrix24Channel_GroupChat_MentionRequired` — group DIALOG_ID without mention → ignored
- `TestBitrix24Channel_GroupChat_MentionPresent` — group DIALOG_ID with `[USER=botID]` → processed
- `TestBitrix24Channel_GroupChat_RespondAll` — GroupRespondAll=true → all group messages processed
- `TestBitrix24Channel_WebhookBaseURL` — confirm `webhookBaseURL()` returns configured value
- Update existing `TestSplitBitrix24Message*` tests to use/verify `utils.SplitMessage` behaviour

---

## Out of scope (Phase 2)

- Multi-file attachment handling (waits for upstream #348)
- Retry with exponential backoff
- Extended BBCode (ordered lists, italic edge cases)

---

## File impact summary

| File | Change type |
|------|-------------|
| `pkg/channels/bitrix24.go` | Modify (struct, DRY refactor, dedup, group chat, sendTyping) |
| `pkg/channels/bitrix24_test.go` | Modify (new tests, update split tests) |
| `pkg/config/config.go` | Modify (2 new fields in Bitrix24Config + defaults) |

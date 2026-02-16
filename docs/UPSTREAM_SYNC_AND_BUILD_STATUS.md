# Upstream Sync And Build Status

Last updated: February 16, 2026

## Scope

This document captures the current fork sync state, merge status, and compile verification workflow for this repository.

## Repository Topology

- `origin`: `https://github.com/jaaacki/picoclaw.git`
- `upstream`: `https://github.com/sipeed/picoclaw`
- Working branch at time of update: `milestone/bitrix24-channel`

Important clarification:

- Upstream is not organized into one local folder.
- Upstream is the `upstream/main` branch (remote-tracking history) mapped across the same repository tree.
- Fork-only ownership is policy-based (`fork/`, `docs/`, `scripts/`, `.github/workflows/fork-guard.yml`), not directory-separated by Git itself.

## Sync Snapshot

At the time of this snapshot:

- `upstream/main`: `8d757fb`
- `origin/main`: `214b201`
- merge commit on working branch: `8e7191e` (merged `upstream/main` into `milestone/bitrix24-channel`)

Current divergence (run these to re-check):

```bash
git rev-list --left-right --count upstream/main...HEAD
git rev-list --left-right --count origin/main...HEAD
```

Interpretation:

- `upstream/main...HEAD` => `0 10` (HEAD is synced with upstream tip and has 10 fork-only commits)
- `origin/main...HEAD` => `0 27` (HEAD is 27 commits ahead of origin/main)

## Merge Notes

`upstream/main` was merged into `milestone/bitrix24-channel` and produced one conflict:

- `cmd/picoclaw/main.go`

Resolution kept both:

- upstream channel-manager injection for command handling (`agentLoop.SetChannelManager(...)`)
- fork generic transcriber flow (`voice.Transcriber` + OpenAI-compatible transcriber config fallback to Groq)

## Compile Verification

Container build command used:

```bash
docker build -t picoclaw:local-compile .
```

Runtime sanity check:

```bash
docker run --rm picoclaw:local-compile version
```

Result: compile and runtime check passed.

## Post-Merge Build Fix Applied

A merge-time symbol collision was found during container compile:

- `pkg/channels/discord.go` and `pkg/channels/bitrix24.go` both defined package-level `splitMessage`

Fix:

- renamed Bitrix24 helper to `splitBitrix24Message` in `pkg/channels/bitrix24.go`

## Fast Re-Validation Checklist

```bash
git fetch --all --prune
git rev-list --left-right --count upstream/main...HEAD
docker build -t picoclaw:local-compile .
docker run --rm picoclaw:local-compile version
```

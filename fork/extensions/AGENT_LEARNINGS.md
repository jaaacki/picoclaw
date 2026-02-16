# Agent Learnings (Fork Local)

Last updated: 2026-02-16

This file records fork-specific operating lessons without editing upstream `workspace/AGENT.md`.

## Today's Learnings

- Upstream is not a single local folder; it is the `upstream/main` branch over the same tree.
- Treat upstream files as read-only by default.
- Do normal work in fork-owned zones:
  - `fork/`
  - `docs/`
  - `scripts/`
  - `.github/workflows/fork-guard.yml`
- Use `scripts/fork_guard.sh` before push:
  - `--mode strict` for fork-only edits
  - `--mode baseline` during migration
  - `--mode sync` for report-only during upstream merge work
- Keep docs current in the same change set:
  - `ROADMAP.md`
  - `LEARNING_LOG.md`
  - `CHANGELOG.md`
- For unavoidable upstream touches, make the exception explicit and review-visible.

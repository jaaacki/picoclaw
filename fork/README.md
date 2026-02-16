# Fork Structure And Rules

This fork follows an upstream-first model.

Golden rule:

- Do not touch upstream files if possible.

## Fork-Owned Zones

Only these paths should be modified for normal feature work:

- `fork/`
- `docs/`
- `scripts/`
- `.github/workflows/fork-guard.yml`

Everything else is treated as upstream-owned.

## When Upstream Files Must Be Touched

Allowed only for:

- upstream sync/merge commits
- unavoidable integration fixes
- security hotfixes

Use an explicit override in PR title:

- include `[allow-upstream-touch]`

This keeps exceptions visible and reviewable.

## Guard Script

Use the guard locally before pushing:

```bash
scripts/fork_guard.sh --mode strict --from upstream/main --to HEAD
```

Modes:

- `strict`: only fork-owned zones are allowed
- `baseline`: allows fork-owned zones plus files listed in `fork/upstream_touch_baseline.txt`
- `sync`: report only (never fails)

## Transition Baseline

`fork/upstream_touch_baseline.txt` tracks existing fork/upstream divergence at the time this guard was introduced.

Use it only as a temporary migration aid, not as a long-term policy.

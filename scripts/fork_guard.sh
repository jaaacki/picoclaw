#!/usr/bin/env bash
set -euo pipefail

MODE="strict"
FROM_REF="upstream/main"
TO_REF="HEAD"
ALLOW_FILE="fork/allowed_prefixes.txt"
BASELINE_FILE="fork/upstream_touch_baseline.txt"

usage() {
  cat <<'EOF'
Usage:
  scripts/fork_guard.sh [--mode strict|baseline|sync] [--from <git-ref>] [--to <git-ref>]

Examples:
  scripts/fork_guard.sh --mode strict --from upstream/main --to HEAD
  scripts/fork_guard.sh --mode baseline --from origin/main --to HEAD
  scripts/fork_guard.sh --mode sync --from <base_sha> --to <head_sha>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --from)
      FROM_REF="${2:-}"
      shift 2
      ;;
    --to)
      TO_REF="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$MODE" != "strict" && "$MODE" != "baseline" && "$MODE" != "sync" ]]; then
  echo "Invalid mode: $MODE (expected strict|baseline|sync)" >&2
  exit 2
fi

if [[ ! -f "$ALLOW_FILE" ]]; then
  echo "Missing allowlist file: $ALLOW_FILE" >&2
  exit 2
fi

if ! git rev-parse --verify "$FROM_REF" >/dev/null 2>&1; then
  # Try best-effort fetch for common upstream reference.
  git fetch upstream main --quiet >/dev/null 2>&1 || true
fi

if ! git rev-parse --verify "$FROM_REF" >/dev/null 2>&1; then
  echo "Base ref not found: $FROM_REF" >&2
  exit 2
fi

if ! git rev-parse --verify "$TO_REF" >/dev/null 2>&1; then
  echo "Target ref not found: $TO_REF" >&2
  exit 2
fi

mapfile -t changed_files < <(git diff --name-only --diff-filter=ACMR "${FROM_REF}...${TO_REF}" | sed '/^[[:space:]]*$/d')

if [[ ${#changed_files[@]} -eq 0 ]]; then
  echo "fork_guard: no changed files in range ${FROM_REF}...${TO_REF}"
  exit 0
fi

if [[ "$MODE" == "sync" ]]; then
  echo "fork_guard(sync): reporting changed files for ${FROM_REF}...${TO_REF}"
  printf '  - %s\n' "${changed_files[@]}"
  exit 0
fi

is_allowed_prefix() {
  local file="$1"
  local prefix
  while IFS= read -r prefix || [[ -n "$prefix" ]]; do
    [[ -z "$prefix" || "${prefix:0:1}" == "#" ]] && continue
    if [[ "$file" == "$prefix"* ]]; then
      return 0
    fi
  done < "$ALLOW_FILE"
  return 1
}

is_in_baseline() {
  local file="$1"
  [[ -f "$BASELINE_FILE" ]] || return 1
  grep -Fxq "$file" "$BASELINE_FILE"
}

violations=()

for f in "${changed_files[@]}"; do
  if is_allowed_prefix "$f"; then
    continue
  fi

  if [[ "$MODE" == "baseline" ]] && is_in_baseline "$f"; then
    continue
  fi

  violations+=("$f")
done

if [[ ${#violations[@]} -eq 0 ]]; then
  echo "fork_guard(${MODE}): PASS"
  exit 0
fi

echo "fork_guard(${MODE}): FAIL"
echo "The following files are outside allowed fork-owned zones:"
printf '  - %s\n' "${violations[@]}"
echo
echo "Allowed prefixes file: $ALLOW_FILE"
if [[ "$MODE" == "baseline" ]]; then
  echo "Baseline file: $BASELINE_FILE"
fi
echo
echo "If this is an intentional upstream touch, use explicit override policy in PR title:"
echo "  [allow-upstream-touch]"
exit 1

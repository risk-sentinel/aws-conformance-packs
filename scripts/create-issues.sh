#!/usr/bin/env bash
#
# Create the domain pack issues from markdown files with YAML front matter.
#
# Each file carries `title:` and `labels:` in front matter; everything after the
# closing --- becomes the issue body.
#
# Safe to rerun: existing labels are updated, and issues whose titles are
# already open are skipped. Transient network failures are retried.
#
# Usage:
#   DRY_RUN=1 ./create-issues.sh                              # preview
#   REPO=risk-sentinel/aws-conformance-packs ./create-issues.sh
#   ISSUE_DIR=. ./create-issues.sh                            # flat layout
#
# Requires: gh (authenticated), awk.

set -uo pipefail   # deliberately NOT -e; failures are handled per operation

REPO="${REPO:-}"
DRY_RUN="${DRY_RUN:-0}"
ISSUE_DIR="${ISSUE_DIR:-}"
RETRIES="${RETRIES:-4}"
PACE="${PACE:-1}"   # seconds between content-creating calls

command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 1; }

gh_args=()
[[ -n "$REPO" ]] && gh_args+=(--repo "$REPO")

# Locate the issue files: explicit ISSUE_DIR, else issues/, else here.
if [[ -z "$ISSUE_DIR" ]]; then
  if compgen -G "issues/*.md" >/dev/null; then
    ISSUE_DIR="issues"
  else
    ISSUE_DIR="."
  fi
fi
echo "==> reading issues from: $ISSUE_DIR/"

# ---------------------------------------------------------------------------
# retry wrapper: retries on timeouts, 5xx, and rate limiting; not on 404/422
# ---------------------------------------------------------------------------
run_with_retry() {
  local desc="$1"; shift
  local attempt=1 out rc
  while :; do
    out="$("$@" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then
      RETRY_OUT="$out"; return 0
    fi
    if grep -qiE 'already exists' <<<"$out"; then
      RETRY_OUT="$out"; return 2          # caller decides what to do
    fi
    if grep -qiE 'i/o timeout|timed out|connection reset|EOF|no such host|temporary failure|HTTP 5[0-9][0-9]|rate limit|secondary rate' <<<"$out" \
       && (( attempt < RETRIES )); then
      local wait=$(( attempt * 3 ))
      echo "    .. $desc failed (attempt $attempt/$RETRIES), retrying in ${wait}s"
      sleep "$wait"
      (( attempt++ ))
      continue
    fi
    RETRY_OUT="$out"; return 1
  done
}

# ---------------------------------------------------------------------------
# labels
# ---------------------------------------------------------------------------
label_names=(
  epic planning pack needs-design
  "domain:iam" "domain:net" "domain:crypto"
  "domain:log" "domain:vcm" "domain:rpl" "domain:gov"
)
label_meta() {
  case "$1" in
    epic)           echo "8250df|Tracking issue spanning multiple packs" ;;
    planning)       echo "0e8a16|Scoping and design" ;;
    pack)           echo "1d76db|Conformance pack work" ;;
    needs-design)   echo "fbca04|Approach not settled" ;;
    domain:iam)     echo "c5def5|Identity and access" ;;
    domain:net)     echo "c5def5|Network and boundary" ;;
    domain:crypto)  echo "c5def5|Cryptography and data protection" ;;
    domain:log)     echo "c5def5|Logging, monitoring, audit" ;;
    domain:vcm)     echo "c5def5|Vulnerability and configuration management" ;;
    domain:rpl)     echo "c5def5|Resilience and recovery" ;;
    domain:gov)     echo "c5def5|Governance and policy evidence" ;;
    *)              echo "ededed|" ;;
  esac
}

echo "==> ensuring labels"
label_failures=0
for name in "${label_names[@]}"; do
  meta="$(label_meta "$name")"
  color="${meta%%|*}"
  desc="${meta#*|}"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "    would ensure: $name"
    continue
  fi

  run_with_retry "label $name" \
    gh label create "$name" --color "$color" --description "$desc" \
    "${gh_args[@]+"${gh_args[@]}"}"
  case $? in
    0) echo "    + $name" ;;
    2) run_with_retry "label edit $name" \
         gh label edit "$name" --color "$color" --description "$desc" \
         "${gh_args[@]+"${gh_args[@]}"}" >/dev/null
       echo "    = $name (existed)" ;;
    *) echo "    !! $name: ${RETRY_OUT//$'\n'/ }"
       (( label_failures++ )) ;;
  esac
  sleep "$PACE"
done

if (( label_failures > 0 )); then
  echo "==> $label_failures label(s) unavailable; issues will still be created,"
  echo "    but any missing label will be dropped from its issue."
fi

# ---------------------------------------------------------------------------
# existing issues (for dedupe)
# ---------------------------------------------------------------------------
existing=""
if [[ "$DRY_RUN" != "1" ]]; then
  run_with_retry "issue list" \
    gh issue list --state all --limit 300 --json title --jq '.[].title' \
    "${gh_args[@]+"${gh_args[@]}"}"
  if [[ $? -eq 0 ]]; then
    existing="$RETRY_OUT"
  else
    echo "!! could not list existing issues; duplicates are possible" >&2
  fi
fi

# ---------------------------------------------------------------------------
# issues
# ---------------------------------------------------------------------------
created=0; skipped=0; failed=0
shopt -s nullglob
files=("$ISSUE_DIR"/*.md)
(( ${#files[@]} )) || { echo "no .md files in $ISSUE_DIR" >&2; exit 1; }

for file in "${files[@]}"; do
  title="$(awk '/^title:/ {sub(/^title: */,""); gsub(/^"|"$/,""); print; exit}' "$file")"
  labels="$(awk '/^labels:/ {sub(/^labels: */,""); print; exit}' "$file")"
  body="$(awk 'BEGIN{n=0} /^---[[:space:]]*$/{n++; next} n>=2' "$file")"

  if [[ -z "$title" ]]; then
    continue   # not an issue file (README, LICENSE, etc.)
  fi
  if [[ -z "${body//[[:space:]]/}" ]]; then
    echo "!! $(basename "$file"): empty body, skipping" >&2
    (( failed++ )); continue
  fi

  if [[ -n "$existing" ]] && grep -Fxq "$title" <<<"$existing"; then
    echo "==  exists, skipping: $title"
    (( skipped++ )); continue
  fi

  label_args=()
  IFS=',' read -ra parts <<<"$labels"
  for l in "${parts[@]}"; do
    l="$(echo "$l" | xargs)"
    [[ -n "$l" ]] && label_args+=(--label "$l")
  done

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "++  would create: $title  [$labels]  ($(wc -c <<<"$body") bytes)"
    (( created++ )); continue
  fi

  tmp="$(mktemp)"; printf '%s\n' "$body" >"$tmp"
  run_with_retry "issue $title" \
    gh issue create --title "$title" --body-file "$tmp" \
    "${label_args[@]+"${label_args[@]}"}" "${gh_args[@]+"${gh_args[@]}"}"
  rc=$?
  rm -f "$tmp"

  if [[ $rc -eq 0 ]]; then
    echo "++  $title"
    grep -o 'https://github.com/[^ ]*' <<<"$RETRY_OUT" | sed 's/^/    /'
    (( created++ ))
  else
    echo "!!  $title: ${RETRY_OUT//$'\n'/ }" >&2
    (( failed++ ))
  fi
  sleep "$PACE"
done

echo "==> created $created, skipped $skipped, failed $failed"
(( failed > 0 )) && echo "    rerun to pick up the failures — already-open titles are skipped"
exit 0
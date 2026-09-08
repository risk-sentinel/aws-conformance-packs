#!/usr/bin/env bash
#
# Deploy the rendered conformance packs named in inputs.yml.
#
# Run by .github/workflows/deploy.yml and by ci/gitlab/deploy.yml, and directly
# by anyone who would rather not use either. It assumes credentials are already
# in the environment; it never assumes a role itself.
#
# TWO BEHAVIOURS WORTH KNOWING BEFORE YOU RUN IT
#
#   put-conformance-pack is CREATE-OR-UPDATE. Re-running updates in place, which
#   is what you want: evaluation history survives.
#
#   DELETING a pack destroys its evaluation history. So removing a pack from
#   `packs` in inputs.yml does NOT delete it. The orphan is reported and left
#   alone. Deletion is a deliberate manual act, because it is not recoverable.

set -uo pipefail

INPUTS="${INPUTS:-inputs.yml}"
OUT="${OUT:-out}"

command -v aws >/dev/null || { echo "::error::aws CLI not found" >&2; exit 1; }
[[ -f "$INPUTS" ]] || { echo "::error::$INPUTS not found" >&2; exit 1; }

y() { python3 -c "import yaml,sys;d=yaml.safe_load(open('$INPUTS'));print($1)"; }

MODE=$(y "d['mode']")
PACKS=$(y "' '.join(d['packs'])")
REGIONS=$(y "' '.join(d['regions'])")
GLOBAL_REGION=$(y "d.get('global_resource_region') or ''")
PACK_BUCKET=$(y "(d.get('delivery') or {}).get('pack_bucket') or ''")
EVIDENCE_BUCKET=$(y "(d.get('delivery') or {}).get('evidence_bucket') or ''")
EXCLUDED=$(y "' '.join((d.get('excluded_accounts') or []))")

# AWS's inline template limit. Past it the template must be staged in S3, and
# the decision is made per pack from what actually rendered rather than assumed.
INLINE_LIMIT=51200

echo "mode=$MODE packs=[$PACKS] regions=[$REGIONS]"
failures=0; deployed=0

for pack in $PACKS; do
  slug=$(python3 - "$pack" <<'PY'
import sys,glob,yaml
for f in glob.glob('rules/*.yaml'):
    d=yaml.safe_load(open(f))
    if d['domain']==sys.argv[1]: print(d['pack_slug']); break
PY
)
  tpl="$OUT/$slug.yaml"
  [[ -f "$tpl" ]] || { echo "::error::$tpl not rendered"; failures=$((failures+1)); continue; }
  size=$(wc -c <"$tpl" | tr -d ' ')

  # IAM is global. Deployed outside the Region that records global resources it
  # evaluates nothing and reports INSUFFICIENT_DATA everywhere — which reads as
  # "not failing". So it is pinned rather than fanned out.
  if [[ "$pack" == "IAM" ]]; then
    targets="$GLOBAL_REGION"
    echo "  $pack is global-scoped; deploying only to $GLOBAL_REGION"
  else
    targets="$REGIONS"
  fi

  for region in $targets; do
    name=$(echo "$slug" | tr '[:upper:]' '[:lower:]')
    args=(--conformance-pack-name "$name" --delivery-s3-bucket "$EVIDENCE_BUCKET")

    if (( size > INLINE_LIMIT )); then
      [[ -n "$PACK_BUCKET" ]] || {
        echo "::error::$slug is $size bytes, over the ${INLINE_LIMIT}-byte inline limit, and delivery.pack_bucket is empty. Set it."
        failures=$((failures+1)); continue; }
      key="packs/$slug.yaml"
      aws s3 cp "$tpl" "s3://$PACK_BUCKET/$key" --region "$region" >/dev/null || {
        echo "::error::staging $slug to s3://$PACK_BUCKET/$key failed"; failures=$((failures+1)); continue; }
      args+=(--template-s3-uri "s3://$PACK_BUCKET/$key")
      echo "  $slug -> $region (staged, $size bytes)"
    else
      args+=(--template-body "file://$tpl")
      echo "  $slug -> $region (inline, $size bytes)"
    fi

    if [[ "$MODE" == "organization" ]]; then
      cmd=(aws configservice put-organization-conformance-pack
           --organization-conformance-pack-name "$name" "${args[@]:2}")
      cmd+=(--delivery-s3-bucket "$EVIDENCE_BUCKET")
      [[ -n "$EXCLUDED" ]] && cmd+=(--excluded-accounts $EXCLUDED)
    else
      cmd=(aws configservice put-conformance-pack "${args[@]}")
    fi

    if "${cmd[@]}" --region "$region" >/dev/null; then
      deployed=$((deployed+1))
    else
      echo "::error::deploying $slug to $region failed"; failures=$((failures+1))
    fi
  done
done

# Report packs that exist in the account but are no longer selected. Never
# delete them: deletion destroys evaluation history and is not recoverable.
for region in $REGIONS; do
  existing=$(aws configservice describe-conformance-packs --region "$region" \
    --query 'ConformancePackDetails[].ConformancePackName' --output text 2>/dev/null || true)
  for e in $existing; do
    keep=0
    for pack in $PACKS; do
      s=$(python3 - "$pack" <<'PY'
import sys,glob,yaml
for f in glob.glob('rules/*.yaml'):
    d=yaml.safe_load(open(f))
    if d['domain']==sys.argv[1]: print(d['pack_slug'].lower()); break
PY
)
      [[ "$e" == "$s" ]] && keep=1
    done
    (( keep )) || echo "::warning::$region has conformance pack '$e', which inputs.yml no longer selects. NOT deleted — deleting destroys its evaluation history. Remove it deliberately if that is what you want."
  done
done

echo "deployed $deployed, failed $failures"
(( failures == 0 ))

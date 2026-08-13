#!/bin/bash
# Fill the prompt templates in prompts/ with the real values from the deployed
# stack and write the result to prompts/rendered/.
#
# The templates are committed; the rendered output is not, because it contains
# your account ID and resource IDs. prompts/rendered/ is in .gitignore for that
# reason. Paste a rendered file into the investigation when you start it.
set -uo pipefail

STACK="${STACK:-devops-agent-security-triage}"
# Credentials: set PROFILE=yourprofile to pin a named profile. Otherwise the AWS
# CLI resolves credentials its usual way, which already honours AWS_PROFILE,
# environment variables and SSO, so a reader who deployed the stack with their
# default profile does not have to configure anything here.
if [ -n "${PROFILE:-}" ]; then
  export AWS_PROFILE="$PROFILE"
fi
REGION="${REGION:-us-east-1}"
PREFIX="${PREFIX:-sectriage}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/prompts"
DEST="$SRC/rendered"

out() { aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if [ -z "$ACCOUNT_ID" ] || [ "$ACCOUNT_ID" = "None" ]; then
  echo "Could not resolve the account ID. Check that profile '$PROFILE' works." >&2
  exit 1
fi

SECURITY_GROUP_ID=$(out SecurityGroupId)
INSTANCE_ID=$(out InstanceId)
TRAIL_BUCKET=$(out TrailBucketName)
LAB_BUCKET=$(out LabDataBucketName)

for v in SECURITY_GROUP_ID INSTANCE_ID TRAIL_BUCKET LAB_BUCKET; do
  if [ -z "${!v}" ] || [ "${!v}" = "None" ]; then
    echo "Stack output for $v is empty. Is stack '$STACK' deployed in $REGION?" >&2
    exit 1
  fi
done

mkdir -p "$DEST"
for f in "$SRC"/scenario*.txt; do
  name="$(basename "$f")"
  sed -e "s|__ACCOUNT_ID__|$ACCOUNT_ID|g" \
      -e "s|__REGION__|$REGION|g" \
      -e "s|__PREFIX__|$PREFIX|g" \
      -e "s|__SECURITY_GROUP_ID__|$SECURITY_GROUP_ID|g" \
      -e "s|__INSTANCE_ID__|$INSTANCE_ID|g" \
      -e "s|__TRAIL_BUCKET__|$TRAIL_BUCKET|g" \
      -e "s|__LAB_BUCKET__|$LAB_BUCKET|g" \
      "$f" > "$DEST/$name"
  echo "  wrote prompts/rendered/$name"
done

echo
if grep -rl "__[A-Z_]*__" "$DEST" >/dev/null 2>&1; then
  echo "WARNING: unreplaced placeholders remain:"
  grep -ro "__[A-Z_]*__" "$DEST" | sort -u
  exit 1
fi
echo "All placeholders resolved. prompts/rendered/ is gitignored, so it will not be committed."

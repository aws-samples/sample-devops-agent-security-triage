#!/bin/bash
# Scenario 1, OWASP A01:2025 Broken Access Control.
#
# Runs entirely as the scoped demo user, using its own credentials, so every
# call is attributable to that principal in CloudTrail. The sequence is:
# reconnaissance, create a second access key, attempt a privilege escalation
# that the user's policy denies, then read lab objects in bulk.
#
# The escalation is expected to fail with AccessDenied. That failure is the
# finding, not a bug in the script.
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
READS="${READS:-120}"

out() { aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

BUCKET=$(out LabDataBucketName)
DEMO_USER=$(out DemoUserName)
AKID=$(out DemoAccessKeyId)

# The secret access key is held in Secrets Manager, not in a stack output, so it
# is not exposed to every principal with cloudformation:DescribeStacks. This call
# runs as whoever is executing the script and needs secretsmanager:GetSecretValue.
SECRET_ARN=$(out DemoCredentialsSecretArn)
SECRET=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
  --region "$REGION" --query SecretString --output text 2>/dev/null)
if [ -z "${SECRET:-}" ] || [ "$SECRET" = "None" ]; then
  echo "Could not read the demo user's secret from Secrets Manager." >&2
  echo "  secret: ${SECRET_ARN:-<no DemoCredentialsSecretArn output found>}" >&2
  echo "  Check that the stack is deployed and that this identity has" >&2
  echo "  secretsmanager:GetSecretValue on that secret." >&2
  exit 1
fi

echo "Scenario 1: credential misuse as $DEMO_USER"
echo "  bucket: $BUCKET"
echo

# Use the demo credentials directly. Nothing here runs as the admin principal.
export AWS_ACCESS_KEY_ID="$AKID"
export AWS_SECRET_ACCESS_KEY="$SECRET"
export AWS_DEFAULT_REGION="$REGION"
unset AWS_SESSION_TOKEN AWS_PROFILE

step() { printf '  %-42s ' "$1"; }

step "whoami (GetCallerIdentity)"
aws sts get-caller-identity --query Arn --output text 2>&1 | tail -1

step "recon: ListUsers"
aws iam list-users --query 'length(Users)' --output text 2>&1 | tail -1

step "recon: ListAttachedUserPolicies"
aws iam list-attached-user-policies --user-name "$DEMO_USER" \
  --query 'length(AttachedPolicies)' --output text 2>&1 | tail -1

step "persistence: CreateAccessKey"
NEW_KEY=$(aws iam create-access-key --user-name "$DEMO_USER" \
  --query 'AccessKey.AccessKeyId' --output text 2>&1 | tail -1)
echo "$NEW_KEY"
if [[ "$NEW_KEY" == AKIA* ]]; then
  echo "$NEW_KEY" > /tmp/sectriage-second-key-id
  echo "     (recorded in /tmp/sectriage-second-key-id for teardown)"
fi

step "escalation: AttachUserPolicy (expect denied)"
ESC=$(aws iam attach-user-policy --user-name "$DEMO_USER" \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>&1)
if echo "$ESC" | grep -q "AccessDenied"; then
  echo "AccessDenied (expected)"
else
  echo "UNEXPECTEDLY SUCCEEDED, revoke immediately: $ESC"
fi

step "bulk read: listing objects"
KEYS=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "customer-records/" \
  --query 'Contents[].Key' --output text 2>&1 | tr '\t' '\n' | head -"$READS")
COUNT=$(echo "$KEYS" | grep -c . || true)
echo "$COUNT keys"

echo "  bulk read: issuing GetObject calls"
n=0
while IFS= read -r key; do
  [ -z "$key" ] && continue
  aws s3api get-object --bucket "$BUCKET" --key "$key" /dev/null >/dev/null 2>&1 && n=$((n+1))
done <<< "$KEYS"
echo "     $n objects read from customer-records/"

echo
echo "Done. CloudTrail typically delivers these events within about five minutes,"
echo "and the alarm cannot fire until the CreateAccessKey event lands. Wait for"
echo "delivery before starting the investigation."

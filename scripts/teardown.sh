#!/bin/bash
# Teardown. Removes everything the lab created, in an order that will not leave
# orphans. Run this as soon as the screenshots are captured.
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

out() { aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text 2>/dev/null; }

DEMO_USER=$(out DemoUserName)
LAB_BUCKET=$(out LabDataBucketName)
TRAIL_BUCKET=$(out TrailBucketName)

echo "Teardown of $STACK in account $(aws sts get-caller-identity --query Account --output text)"
echo

# 1. The second access key the scenario one script created is not managed by
#    CloudFormation, so the stack delete will fail on the user unless it goes first.
if [ -n "${DEMO_USER:-}" ] && [ "$DEMO_USER" != "None" ]; then
  echo "  deleting non-stack access keys on $DEMO_USER"
  STACK_KEY=$(out DemoAccessKeyId)
  for k in $(aws iam list-access-keys --user-name "$DEMO_USER" \
      --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
    if [ "$k" != "$STACK_KEY" ]; then
      aws iam update-access-key --user-name "$DEMO_USER" --access-key-id "$k" \
        --status Inactive 2>/dev/null || true
      aws iam delete-access-key --user-name "$DEMO_USER" --access-key-id "$k" 2>/dev/null && echo "    deleted $k"
    fi
  done
fi

# 1b. The demo user secret is a named Secrets Manager secret. A normal delete
#     leaves it in a recovery window, and a redeploy would then fail because the
#     name is still taken, so force delete it.
SECRET_ARN=$(out DemoCredentialsSecretArn)
if [ -n "${SECRET_ARN:-}" ] && [ "$SECRET_ARN" != "None" ]; then
  echo "  force deleting the demo user secret"
  aws secretsmanager delete-secret --secret-id "$SECRET_ARN" \
    --force-delete-without-recovery --region "$REGION" >/dev/null 2>&1 \
    && echo "    deleted, no recovery window" \
    || echo "    could not delete, remove it by hand if a redeploy complains"
fi

# 2. Buckets must be empty before the stack can delete them. With versioning
#    enabled, 'aws s3 rm --recursive' only creates delete markers. We must
#    delete all object versions and delete markers explicitly.
empty_versioned_bucket() {
  local bucket="$1"
  echo "  emptying s3://$bucket (all versions)"
  local token=""
  while true; do
    if [ -z "$token" ]; then
      page=$(aws s3api list-object-versions --bucket "$bucket" --region "$REGION" \
        --output json --max-items 1000 2>/dev/null)
    else
      page=$(aws s3api list-object-versions --bucket "$bucket" --region "$REGION" \
        --output json --max-items 1000 --starting-token "$token" 2>/dev/null)
    fi
    # Build delete payload from Versions and DeleteMarkers
    objects=$(echo "$page" | jq -c '[(.Versions // [])[] | {Key, VersionId}] + [(.DeleteMarkers // [])[] | {Key, VersionId}]')
    count=$(echo "$objects" | jq 'length')
    if [ "$count" -gt 0 ]; then
      echo "$objects" | jq -c '{Objects: ., Quiet: true}' | \
        aws s3api delete-objects --bucket "$bucket" --region "$REGION" --delete file:///dev/stdin >/dev/null 2>&1
    fi
    token=$(echo "$page" | jq -r '.NextToken // empty')
    [ -z "$token" ] && break
  done
}

PREFIX=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Parameters[?ParameterKey=='NamePrefix'].ParameterValue" --output text 2>/dev/null)
PREFIX="${PREFIX:-sectriage}"
ACCT=$(aws sts get-caller-identity --query Account --output text)
LOGGING_BUCKET="${PREFIX}-access-logs-${ACCT}-${REGION}"
for b in "$LAB_BUCKET" "$TRAIL_BUCKET" "$LOGGING_BUCKET"; do
  if [ -n "${b:-}" ] && [ "$b" != "None" ]; then
    empty_versioned_bucket "$b"
  fi
done

# 3. Delete the stack. This removes the trail, the data event selectors, the
#    demo user and its stack-managed key, the VPC and instance, the API, the
#    alarms, the metric filters, and every log group the stack created.
echo "  deleting stack"
aws cloudformation delete-stack --stack-name "$STACK" --region "$REGION"
echo "  waiting for delete to complete"
aws cloudformation wait stack-delete-complete --stack-name "$STACK" --region "$REGION" && echo "  stack deleted" \
  || echo "  wait returned non-zero. Check the stack events for the blocking resource."

echo
echo "Remaining manual step: if an Agent Space was created only for this lab,"
echo "delete it with:"
echo "  aws devops-agent delete-agent-space --agent-space-id <id> --profile $PROFILE --region $REGION"

#!/bin/bash
# Seed the lab bucket with synthetic records. Every value is generated, so no
# real data is involved. Names come from the AWS Style Guide fictitious-names
# guidance and addresses come from the RFC 5737 documentation ranges.
set -euo pipefail

STACK="${STACK:-devops-agent-security-triage}"
# Credentials: set PROFILE=yourprofile to pin a named profile. Otherwise the AWS
# CLI resolves credentials its usual way, which already honours AWS_PROFILE,
# environment variables and SSO, so a reader who deployed the stack with their
# default profile does not have to configure anything here.
if [ -n "${PROFILE:-}" ]; then
  export AWS_PROFILE="$PROFILE"
fi
REGION="${REGION:-us-east-1}"

BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='LabDataBucketName'].OutputValue" --output text)

echo "Seeding s3://$BUCKET"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# customer-records/
for i in $(seq -w 1 40); do
  cat > "$TMP/customer-$i.json" <<EOF
{
  "record_id": "cust-$i",
  "name": "Carlos Salazar",
  "email": "carlos@example.com",
  "phone": "555-0100",
  "city": "Anytown",
  "note": "Synthetic record generated for a lab. Not real customer data."
}
EOF
done

# payment-data/
for i in $(seq -w 1 30); do
  cat > "$TMP/payment-$i.json" <<EOF
{
  "txn_id": "txn-$i",
  "card_last_four": "0000",
  "amount": "$((RANDOM % 500)).00",
  "currency": "USD",
  "note": "Synthetic record generated for a lab. Not real payment data."
}
EOF
done

# internal-reports/
for i in $(seq -w 1 10); do
  cat > "$TMP/report-$i.txt" <<EOF
Quarterly summary $i. Synthetic content generated for a lab.
EOF
done

aws s3 cp "$TMP" "s3://$BUCKET/customer-records/" --recursive \
  --exclude "*" --include "customer-*.json" --region "$REGION" --only-show-errors
aws s3 cp "$TMP" "s3://$BUCKET/payment-data/" --recursive \
  --exclude "*" --include "payment-*.json" --region "$REGION" --only-show-errors
aws s3 cp "$TMP" "s3://$BUCKET/internal-reports/" --recursive \
  --exclude "*" --include "report-*.txt" --region "$REGION" --only-show-errors

echo "Seeded:"
aws s3 ls "s3://$BUCKET/" --recursive --region "$REGION" | wc -l | xargs echo "  objects:"

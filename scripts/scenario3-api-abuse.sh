#!/bin/bash
# Scenario 3, OWASP A05:2025 Injection and A07:2025 Authentication Failures,
# producing an A09:2025 Security Logging and Alerting Failures finding.
#
# Sends a burst at the lab payment API: failed authentication attempts, SQL
# injection strings, and path traversal attempts. The API rejects everything and
# logs each decision as structured JSON including an outcome field, so the
# investigation can state definitively that nothing succeeded.
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
BURST="${BURST:-90}"

ENDPOINT=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='PaymentApiEndpoint'].OutputValue" --output text)

echo "Scenario 3: $BURST requests against $ENDPOINT"
echo

USERS=(admin root svc_payments jsmith operator backup test finance)
SQLI=("' OR 1=1--" "1 UNION SELECT null,null--" "'; DROP TABLE payments--")
TRAV=("../../etc/passwd" "%2e%2e%2f%2e%2e%2fetc%2fpasswd" "/var/www/../../etc/passwd")

auth=0; inj=0; trav=0; codes=""

for i in $(seq 1 "$BURST"); do
  case $((i % 5)) in
    0)
      p="${SQLI[$((RANDOM % ${#SQLI[@]}))]}"
      code=$(curl -s -o /dev/null -w '%{http_code}' -G "$ENDPOINT/login" \
        --data-urlencode "username=admin" --data-urlencode "q=$p" --max-time 10)
      inj=$((inj+1))
      ;;
    1)
      p="${TRAV[$((RANDOM % ${#TRAV[@]}))]}"
      code=$(curl -s -o /dev/null -w '%{http_code}' -G "$ENDPOINT/files" \
        --data-urlencode "path=$p" --max-time 10)
      trav=$((trav+1))
      ;;
    *)
      u="${USERS[$((RANDOM % ${#USERS[@]}))]}"
      code=$(curl -s -o /dev/null -w '%{http_code}' -G "$ENDPOINT/login" \
        --data-urlencode "username=$u" --data-urlencode "password=Passw0rd$i" --max-time 10)
      auth=$((auth+1))
      ;;
  esac
  codes="$codes$code "
  printf '\r  sent %d/%d' "$i" "$BURST"
  sleep 0.15
done
echo

echo
echo "  authentication attempts : $auth"
echo "  injection attempts      : $inj"
echo "  traversal attempts      : $trav"
echo "  distinct status codes   : $(echo $codes | tr ' ' '\n' | sort -u | tr '\n' ' ')"
echo
echo "Any 200 in that list would mean a request got through and this stops being"
echo "a triage exercise. Expect only 400 and 401."
echo
echo "Log group: $(aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='PaymentApiLogGroupName'].OutputValue" --output text)"

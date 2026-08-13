#!/bin/bash
# Scenario 2, OWASP A02:2025 Security Misconfiguration.
#
# Opens port 22 to 0.0.0.0/0 on the lab security group. The instance sits in a
# private subnet with no public IP and the VPC has no internet gateway, so the
# rule is a real, attributable misconfiguration in CloudTrail without creating a
# reachable SSH endpoint. VPC Flow Logs will show no accepted inbound traffic on
# port 22, which is the "exposure without exploitation" outcome the post
# describes and the safer of the two to demonstrate.
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
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

SG=$(out SecurityGroupId)
INSTANCE=$(out InstanceId)

echo "Scenario 2: opening port 22 to 0.0.0.0/0"
echo "  security group: $SG"
echo "  attached to:    $INSTANCE (private subnet, no public IP)"
echo

printf '  %-42s ' "AuthorizeSecurityGroupIngress"
aws ec2 authorize-security-group-ingress \
  --group-id "$SG" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description="lab: opened by scenario 2"}]' --region "$REGION" \
  --query 'Return' --output text 2>&1 | tail -1

echo
echo "  current ingress rules:"
aws ec2 describe-security-groups --group-ids "$SG" --region "$REGION" \
  --query 'SecurityGroups[0].IpPermissions[].{Proto:IpProtocol,From:FromPort,To:ToPort,Cidr:IpRanges[0].CidrIp}' \
  --output table 2>&1 | sed 's/^/    /'

echo
echo "Done. Revert with scripts/revert-security-group.sh, or leave it for the"
echo "investigation and let teardown remove the whole VPC."

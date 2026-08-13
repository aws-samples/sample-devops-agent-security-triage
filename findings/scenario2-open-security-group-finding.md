I have all the information. Here's the complete findings:

───
*Summary*

Security group `sg-0123456789abcdef0` was opened to `0.0.0.0/0` on port 22 (SSH) by IAM user `test_user` at *2026-08-10T02:49:17 UTC*. Despite the exposure, *no inbound SSH traffic has reached the instance* — VPC Flow Logs show only `NODATA` records since the change.

───
*1. Who Made the Change*

Attribute  Value

*Principal ARN*  `arn:aws:iam::111122223333:user/test_user`
*Principal ID*  `AIDACKCEVSQ6C2EXAMPLE`
*Access Key*  `AKIAIOSFODNN7EXAMPLE`
*Source IP*  `203.0.113.42`
*User Agent*  `aws-cli/1.45.55` (macOS arm64, Python 3.10.20)
*Timestamp*  `2026-08-10T02:49:17Z`
*Event ID*  `ed9268c2-19ea-441c-a396-41d926a0f8a7`
*API Call*  `AuthorizeSecurityGroupIngress`
*Rule Created*  `sgr-0123456789abcdef0` — TCP/22 from `0.0.0.0/0`

───
*2. Resources Attached to `sg-0123456789abcdef0`*

Resource  Details

*EC2 Instance*  `i-0123456789abcdef0` (`sectriage-demo-instance`, `t3.micro`, running)
*ENI*  `eni-0123456789abcdef0` (primary interface, attached at device index 0)
*Private IP*  `10.20.1.204`
*Subnet*  `subnet-0123456789abcdef0` (us-east-1a)
*VPC*  `vpc-0123456789abcdef0`

No other ENIs or resources are associated with this security group — the instance is the sole exposure surface.

───
*3. VPC Flow Logs — Inbound SSH Traffic Since the Change*

*Result: No traffic reached the instance.*

All 21 flow log records for ENI `eni-0123456789abcdef0` from `02:28Z` to `02:55Z` are `NODATA` entries, meaning *zero network packets* (inbound or outbound, any port) traversed the interface during the entire observation window. Specifically:

• ✅ *0* ACCEPT records on port 22
• ✅ *0* REJECT records on port 22
• ✅ *0* traffic of any kind on the ENI

*Conclusion:* The security group misconfiguration has *not yet been exploited*. No SSH connection attempts — legitimate or malicious — have been observed.

───
*Recommendations*

1. *Revoke the rule immediately* — remove security group rule `sgr-0123456789abcdef0`:
   ```
   aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 \
     --security-group-rule-ids sgr-0123456789abcdef0 --region us-east-1
   ```
2. *Investigate the principal* — determine whether `test_user`'s action from `203.0.113.42` was authorized, and consider rotating access key `AKIAIOSFODNN7EXAMPLE` if not.
3. *Preventive controls* — deploy an SCP or AWS Config rule (`restricted-ssh`) to prevent future `0.0.0.0/0` ingress on port 22 across the account.

# Security scanner findings and triage

This lab deliberately creates the conditions a security investigation needs something to find. A
static scanner cannot tell intent from accident, so it will report several of those conditions. This
document exists so a reviewer does not have to work out which is which.

Everything below was verified against the code, with the line references to check. It is organised by
what a scanner reports, not by scanner, so it should map onto whatever tool you run.

## Fixed, was a genuine weakness

### The demo user's secret access key used to be a CloudFormation stack output

Fixed. Previously `template.yaml` exposed `!GetAtt DemoUserAccessKey.SecretAccessKey` as a stack
output, which any principal holding `cloudformation:DescribeStacks` could read, and which persisted in
stack metadata for the life of the stack. The lab framing did not make that acceptable, and sample code
gets copied.

The secret is now held in an `AWS::SecretsManager::Secret` named
`${NamePrefix}-demo-user-secret-access-key`, and the stack outputs only its ARN as
`DemoCredentialsSecretArn`. `scenario1-credential-misuse.sh` reads the value with
`secretsmanager:get-secret-value` at run time and fails with a clear message if it cannot.

Two consequences worth knowing:

- whoever runs scenario 1 needs `secretsmanager:GetSecretValue` on that secret
- `teardown.sh` force deletes the secret with no recovery window, because the secret is named and a
  normal delete would leave the name reserved and block an immediate redeploy

The access key **ID** is still a stack output. An access key ID is an identifier, not a credential, and
it is useless without the secret.

## Intentional, and the point of the lab

### Security group opened to 0.0.0.0/0 on port 22

`scripts/scenario2-open-security-group.sh`.

This is the condition scenario 2 exists to investigate. Worth noting for a reviewer that the exposure
is not reachable:

- the template creates the group **closed**. `0.0.0.0/0` appears in `template.yaml` only in a comment,
  a metric filter pattern and an alarm description, never in an ingress rule.
- the VPC has no internet gateway and no NAT gateway, verified: zero occurrences of either resource
- `MapPublicIpOnLaunch: false`, and the instance has no public IP
- egress is pinned to `127.0.0.1/32`

So the rule is a genuine, attributable misconfiguration in CloudTrail, which is what the scenario
needs, without creating a reachable SSH endpoint. On the recorded run, VPC Flow Logs confirmed zero
packets reached the interface.

### SQL injection and path traversal strings

`scripts/scenario3-api-abuse.sh`, the `SQLI` and `TRAVERSAL` arrays.

These are payloads sent *at* the lab API so it can reject and classify them. There is nothing to
inject into: the API has no database, executes no SQL, and reads no files. The handler pattern matches
the strings, logs a rejection, and returns 400. See `OWASP-MAPPING.md` for the full path.

### An application that logs `source_ip` as "unknown" on every request

`template.yaml`, the handler's `ident` lookup, commented in place.

Deliberate. The handler reads the REST API field name against an HTTP API event, so the lookup always
misses. This produces the A09:2025 logging finding that scenario 3 is built to surface, and it is a
more representative failure than an absent field because the log looks complete. The comment in the
template gives the one line change that closes it.

## False positives

### Strings shaped like AWS access key IDs

Eight occurrences across `findings/scenario1-credential-misuse-finding.md` and
`findings/scenario2-open-security-group-finding.md`.

Every one is `AKEXAMPLEKEYOSFODNN7` or `AKEXAMPLEKEY44QH8DHB`, both published AWS documentation example
values. They match the `AKIA[0-9A-Z]{16}` pattern secret detectors look for, which is why they fire.
No real credential appears anywhere in this repository. The captured findings were sanitised: the
account ID is `111122223333` and addresses are `203.0.113.42`, both documentation ranges.

### `iam:ListUsers` with `Resource: '*'`

`template.yaml`, the `ListUsersForReconnaissance` statement.

`ListUsers` is an account level operation and IAM does not support resource level permissions for it,
so `*` is the only valid value. This cannot be resolved by scoping. Every other action in that policy
is scoped to the demo user's ARN, and `iam:GetUser` and `iam:ListAttachedUserPolicies` were moved into
a scoped statement specifically so this wildcard covers one unavoidable action rather than three.

## Accepted, low severity

Best practice rules that fire on a lab of this size and are not worth resolving here: the Lambda
function has no dead letter queue, no reserved concurrency and no active tracing; log groups use
default encryption rather than a customer managed KMS key. None of these affect the evidence the
scenarios produce, and each would add cost or setup for a stack meant to live for an afternoon.

For completeness, the checks that a scanner might be expected to raise and does not: both S3 buckets
set `BucketEncryption` with AES256, `PublicAccessBlockConfiguration` with all four blocks, and the lab
bucket sets `VersioningConfiguration`. Log retention is bounded by the `LogRetentionDays` parameter,
default 7.

## cfn-guard rules — suppressed by design

The following cfn-guard rules fire against this template. None are actionable for a lab stack.

### CLOUD_TRAIL_ENCRYPTION_ENABLED (KMSKeyId missing on LabTrail)

A CMK for trail encryption adds a KMS key resource, a key policy, and ongoing cost. The trail delivers
to a bucket encrypted at rest with AES256 and to a CloudWatch Logs group. For an afternoon lab whose
evidence is deleted by `teardown.sh`, the default encryption is sufficient.

### CLOUDWATCH_ALARM_ACTION_CHECK (AlarmActions, OKActions, InsufficientDataActions missing)

The three alarms exist so the DevOps Agent can discover and read them during investigation, not so
they page anyone. Adding SNS topics and subscriptions would triple the resource count for no lab
benefit. The alarms are detection artefacts, not operational alerting.

### CLOUDWATCH_LOG_GROUP_ENCRYPTED (KmsKeyId missing on log groups)

Same rationale as trail encryption. CMK adds cost and a key resource for logs that live seven days
maximum and are deleted with the stack.

### CW_LOGGROUP_RETENTION_PERIOD_CHECK (RetentionInDays not a literal)

False positive. The template uses `!Ref LogRetentionDays`, a parameter with
`AllowedValues: [1, 3, 5, 7, 14, 30]`. cfn-guard cannot resolve the Ref at static analysis time but
the parameter constraint ensures only valid values are used.

### EBS_OPTIMIZED_INSTANCE

Fixed — `EbsOptimized: true` added. t3.micro is EBS-optimised by default but the explicit property
silences the rule.

### IAM_NO_INLINE_POLICY_CHECK (inline policies on FlowLogRole, TrailLogsRole, PaymentApiRole)

Every role uses a single scoped inline policy rather than a managed policy, because the lab is
self-contained in one template and the policies are not reused. Converting to managed policies adds
three resources and achieves nothing for a stack deleted after use.

### IAM_USER_LOGIN_PROFILE_USES_SECURE_PARAMETER

The DemoUser has no LoginProfile. The rule fires because it expects one when it sees an IAM user. The
user authenticates only via access keys, never via the console.

### IAM_USER_NO_POLICIES_CHECK (inline policy on DemoUser)

Intentional. The demo user is an isolated lab principal, not a production identity. Managed policies
and groups add indirection that has no value for a disposable, single-purpose user whose permissions
are scoped to the lab bucket and its own IAM context.

### LAMBDA_CONCURRENCY_CHECK (ReservedConcurrentExecutions missing)

Lab Lambda. No production traffic. Reserved concurrency is unnecessary and would add cost if it
reserved capacity that goes unused.

### LAMBDA_DLQ_CHECK (DeadLetterConfig missing)

The function is synchronous behind API Gateway. It returns its response directly to the caller. A DLQ
serves no purpose for synchronous invocations.

### LAMBDA_INSIDE_VPC (VpcConfig missing)

The function has no backend dependencies — no database, no internal API, no private resource. Putting
it in a VPC adds ENI cold start latency, requires NAT for internet access, and solves no security
requirement.

### S3_BUCKET_DEFAULT_LOCK_ENABLED (ObjectLockEnabled missing)

Object Lock requires versioning enabled, prevents object deletion during the retention period, and
makes `teardown.sh` unable to empty and delete the bucket. Incompatible with a lab designed for rapid
deploy/teardown.

### S3_BUCKET_LOGGING_ENABLED

Suppressed via Checkov inline. Access logging requires a destination bucket, which adds a resource, a
policy, and cost for a stack that lives hours.

### S3_BUCKET_NO_PUBLIC_RW_ACL (AccessControl property missing)

Both buckets have `PublicAccessBlockConfiguration` with all four blocks set to `true`, which is the
recommended approach and supersedes ACLs. The missing `AccessControl` property means "private" by
default. cfn-guard flags the absence but the effective state is already private.

### S3_BUCKET_SSL_REQUESTS_ONLY

Fixed — both bucket policies now include a `DenyInsecureTransport` statement.

### S3_BUCKET_VERSIONING_ENABLED

LabDataBucket: versioning is `Suspended` intentionally so the scenario scripts can overwrite seed
data cleanly without accumulating versions.

TrailBucket: versioning is omitted. CloudTrail writes are append-only by key pattern and the bucket
expires all objects after seven days. Versioning would retain expired versions indefinitely unless
lifecycle rules are extended.

### SECRETSMANAGER_ROTATION_ENABLED_CHECK

The secret holds an IAM access key created by the stack. Rotation would require a Lambda rotator,
custom logic to recreate and redistribute the key, and serves no purpose for a key that lives until
teardown deletes it.

### SECRETSMANAGER_USING_CMK (KmsKeyId missing)

Suppressed via Checkov inline. Same rationale as trail encryption: the default `aws/secretsmanager`
key is sufficient for a lab secret that lives hours.

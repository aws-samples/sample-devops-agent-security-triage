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

Every one is `AKIAIOSFODNN7EXAMPLE` or `AKIAI44QH8DHBEXAMPLE`, both published AWS documentation example
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

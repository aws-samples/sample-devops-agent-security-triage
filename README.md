# Security triage lab for AWS DevOps Agent

Companion code for the AWS Cloud Operations blog post "Triage security incidents with AWS DevOps
Agent" (CLOUDOPS-2834).

The lab provisions the evidence sources for three investigations and gives you scripts that generate
the activity each one reasons over. It does not install an agent or change anything about how AWS
DevOps Agent works. It gives the agent something real to read.

> **Deploy this in a sandbox account only.** The stack creates an IAM user with live access keys and
> a security group rule open to `0.0.0.0/0`. Both are intentional, both are what the scenarios
> investigate, and both are removed by `scripts/teardown.sh`.

## What the stack creates

| Resource | Why the lab needs it |
| --- | --- |
| Lab S3 bucket, seeded with generated records | Scenario 1 reads these in bulk, which produces the CloudTrail S3 data events |
| Trail bucket plus a CloudTrail trail | Delivers to Amazon S3 **and** a CloudWatch Logs log group. The metric filters read the log group; the object count comes from the S3 copy, because data events are not available through Event history or `LookupEvents` |
| Scoped demo IAM user and access key | Scenario 1's principal. It can read the lab bucket and enumerate its own IAM context, and it cannot attach policies, so the escalation attempt is denied and recorded as such |
| VPC, private subnet, security group, t3.micro instance, VPC Flow Logs | Scenario 2. The instance has no public IP and the VPC has no internet gateway, so the misconfiguration is real and attributable without creating a reachable SSH endpoint |
| Payment API on Lambda behind API Gateway | Scenario 3. Rejects every request and logs the decision as structured JSON including an `outcome` field |
| Three metric filters and three alarms | The detection logic the post describes, published so you can reproduce it rather than infer it |

Log retention is 7 days and the trail bucket expires objects after 7 days, to bound cost.

## Prerequisites

- A sandbox AWS account and credentials with permission to deploy the stack, plus
  `secretsmanager:GetSecretValue` on the secret the stack creates. Scenario 1 reads the demo user's
  secret access key from AWS Secrets Manager rather than from a stack output.
- An Agent Space in AWS DevOps Agent with the AWS account associated. See
  [Getting started](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-cli-onboarding-guide.html).
- AWS CLI, and `curl` for scenario 3.

## Deploy

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name devops-agent-security-triage \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides NamePrefix=sectriage LogRetentionDays=7

./scripts/seed-lab-data.sh
```

Every script reads its inputs from stack outputs, so there is nothing to copy by hand.

The scripts do not pin a profile. They let the AWS CLI resolve credentials the way it normally does,
so whatever identity deployed the stack above is the identity the scripts use, with no extra
configuration. If you keep the lab in a specific profile, set `PROFILE` and the scripts will export it
as `AWS_PROFILE` for you. `STACK` and `REGION` override the same way:

```bash
PROFILE=my-sandbox REGION=us-west-2 ./scripts/seed-lab-data.sh
```

Deploy and run with the same identity. If you deploy under one profile and run the scripts under
another, the scripts will look for stack outputs that are not there and report empty values.

## Grant the agent read access to the trail bucket

This step is not optional for scenario 1. S3 object reads are CloudTrail **data events**, and data
events do not appear in CloudTrail Event history or the `LookupEvents` API, both of which return
management events only. To count what a principal read, the agent has to read the delivered trail
files in Amazon S3.

`s3:GetObject` and `s3:ListBucket` are inside the agent's permission guardrail but are not granted by
the default `AIDevOpsAgentAccessPolicy`, so attach them to the Agent Space role as an inline policy,
scoped to the trail prefix. Add `kms:Decrypt` as well if you point this at a trail bucket encrypted
with a KMS key.

```bash
TRAIL_BUCKET=$(aws cloudformation describe-stacks --stack-name devops-agent-security-triage \
  --query "Stacks[0].Outputs[?OutputKey=='TrailBucketName'].OutputValue" --output text)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

cat > /tmp/trail-read.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTrailObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${ACCOUNT}/CloudTrail/*"
    },
    {
      "Sid": "ListTrailPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}",
      "Condition": {
        "StringLike": { "s3:prefix": "AWSLogs/${ACCOUNT}/CloudTrail/*" }
      }
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name <your DevOpsAgentRole-AgentSpace-xxxx> \
  --policy-name SecTriageTrailRead \
  --policy-document file:///tmp/trail-read.json
```

## Run the scenarios

Run them **at least 25 minutes apart**. AWS DevOps Agent correlates incoming events over a look-back
window of roughly 20 minutes, so scenarios fired close together can be linked into a single
investigation instead of getting their own.

After each script, wait about five to seven minutes before starting the investigation. CloudTrail
typically delivers events within about five minutes and that time is not guaranteed, so the evidence
may still be in flight.

```bash
./scripts/scenario1-credential-misuse.sh      # OWASP A01:2025
# wait, then investigate

./scripts/scenario2-open-security-group.sh    # OWASP A02:2025
# wait, then investigate

./scripts/scenario3-api-abuse.sh              # OWASP A05:2025 and A07:2025, A09:2025 finding
# wait, then investigate
```

Scenario 1 prints an `AccessDenied` for `AttachUserPolicy`. That is the expected result and it is the
finding the investigation reports, not a script failure.

## Set up an Agent Space and enable the operator app

Do this before running the scenarios. The operator app is the web interface where investigation
results are readable. Without it the CLI will happily report that an investigation completed and you
will have no way to see what it found, which is a confusing place to end up.

Skip to the next section if you already have an Agent Space with the operator app enabled.

```bash
# 1. Create an Agent Space and keep the id it returns
aws devops-agent create-agent-space \
  --name security-triage-lab \
  --description "Lab for the security triage blog post" \
  --region us-east-1

# 2. Confirm the account association is healthy. This has to pass before any
#    investigation can read CloudTrail or CloudWatch Logs.
aws devops-agent validate-aws-associations \
  --agent-space-id <your-agent-space-id> \
  --region us-east-1

# 3. Enable the operator app. authFlow is iam, idc or idp; iam is the least
#    setup. operatorAppRoleArn is the role the web app assumes on your behalf,
#    and it needs a trust policy allowing the DevOps Agent service to assume it.
aws devops-agent enable-operator-app \
  --agent-space-id <your-agent-space-id> \
  --auth-flow iam \
  --operator-app-role-arn arn:aws:iam::<account-id>:role/<your-operator-app-role> \
  --region us-east-1

# 4. Read back the URL. Use this rather than constructing it by hand.
aws devops-agent get-operator-app \
  --agent-space-id <your-agent-space-id> \
  --region us-east-1 \
  --query operatorAppUrl --output text
```

Open that URL and sign in. The Incidents view is where completed investigations appear, and each one
opens onto an investigation timeline showing the agent's reasoning, the tools it called, and the
findings. That timeline is what the figures in the blog post are cropped from.

## Start an investigation

Either wire the alarms to an Agent Space webhook as the post describes, or start an investigation
directly:

```bash
aws devops-agent create-backlog-task \
  --agent-space-id <your-agent-space-id> \
  --task-type INVESTIGATION \
  --title "Unexpected CreateAccessKey by sectriage-demo-user" \
  --description "$(cat prompts/rendered/scenario1.txt)"
```

The prompts in `prompts/` are templates. Render them against your deployed stack first, which fills in
your account ID, security group, instance and bucket names:

```bash
./scripts/render-prompts.sh
```

That writes `prompts/rendered/`, which is gitignored because it contains your account identifiers. The
templates stay the committed source of truth.

## Before you push a change

```bash
./scripts/lint-repo.sh
```

Checks the things that are invisible on the machine a change was written on: a hard coded AWS profile
name, a real account ID or access key ID, a routable IP address, an absolute path into someone's home
directory, an ambiguous OWASP label, and credential material in a stack output. It exists because the
scripts once shipped defaulting to a profile that existed only on the author's laptop, which was
invisible there and broke immediately for the next person to deploy the lab.

## Security scanner findings

This lab creates insecure conditions on purpose, so scanners report them. See
[SCANNER-FINDINGS.md](SCANNER-FINDINGS.md) for a triage of every pattern a scanner flags here, split
into one genuine weakness, the conditions that are the point of the lab, and the false positives, with
line references for each.

## Which code maps to which OWASP category

See [OWASP-MAPPING.md](OWASP-MAPPING.md). It traces each category from the script that generates the
activity, to the metric filter that detects it, to the prompt that investigates it, to the finding it
produced on a real run, with line references into `template.yaml`. The A05:2025 injection path is written
out step by step, including why the alarm deliberately does not detect injection specifically.

The `findings/` directory holds the actual agent output from the run used for the blog post figures.
Account identifiers in those files were replaced with the AWS documentation example values,
`111122223333` and `203.0.113.42`. Counts, timestamps and conclusions are unmodified.

## Teardown

```bash
./scripts/teardown.sh
```

This deactivates and deletes the second access key the scenario 1 script created, which
CloudFormation does not manage, empties both buckets, then deletes the stack. It prints the command
to delete the Agent Space if you created one only for this lab.

If GuardDuty is enabled in the account, expect real findings from scenario 1, most likely in the
Recon, Persistence, and PrivilegeEscalation families. That is a reasonable signal that the lab
worked. Archive them after you are done.

## Security notes

- The demo user's secret access key appears in CloudFormation stack outputs, which is one more reason
  this belongs in a sandbox and why teardown deletes the key.
- Every seeded record is generated. Names and addresses follow the AWS Style Guide fictitious names
  guidance and the RFC 5737 documentation ranges.
- The security group is created closed. Scenario 2 is what opens it, so the change is attributable to
  the principal that ran the script.

## Paused state, as of 2026-08-10

The lab ran end to end for the CLOUDOPS-2834 blog post and is now parked rather than torn down, so
the three completed investigations stay available if a reviewer asks for a different screenshot crop.
Four things were undone after the screenshots were taken:

- The persistence access key that scenario 1 created was deleted. This is the finding's own top
  recommendation, and it also frees the two key per user limit so scenario 1 can run again.
- The `0.0.0.0/0` ingress rule on port 22 that scenario 2 created was revoked. The group has no
  inbound rules again, which is how the template ships it.
- The EC2 instance was stopped. It is the only meaningful recurring cost in the stack.
- Log retention on all three groups is 7 days, so log storage does not grow while the lab sits idle.

The CloudFormation stack, the S3 buckets, the trail, the HTTP API, and the Agent Space are all still
in place. GuardDuty produced no findings attributable to this lab; the one open finding in the
account predates it and concerns an unrelated EKS cluster, so it was left alone.

### Resume the lab

```bash
aws ec2 start-instances --instance-ids "$(out InstanceId)" --region us-east-1
```

Scenario 2 reopens the security group rule on its own, and scenario 1 creates a fresh access key, so
no other setup is needed. Wait for the instance to reach `running` before running scenario 2, because
the Flow Logs half of that investigation needs a live network interface to be meaningful.

### Finish the teardown

```bash
./scripts/teardown.sh
aws devops-agent delete-agent-space --agent-space-id <agent-space-id> --region us-east-1
```

Then delete the `DevOpsAgentRole-WebappAdmin-sectriage` role and remove the `SecTriageTrailRead`
inline policy from the Agent Space execution role. Both were created only to let a browser session
read the trail bucket for these screenshots.

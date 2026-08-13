# OWASP mapping and code traceability

This lab uses the [OWASP Top 10:2025](https://owasp.org/Top10/2025/) numbering. An earlier revision used
the 2021 list, and the two disagree on every identifier this lab touches:

- injection was A03 in 2021 and is A05:2025
- security misconfiguration was A05 in 2021 and is A02:2025
- A03 in 2021 was injection; A03:2025 is Software Supply Chain Failures

That last line is why the renumbering was not optional. Under the older 2021 labels, scenario 3 and the
new supply chain scenario would carry the same identifier, giving the post two different meanings for
one label.

| Scenario | OWASP category | Generates | Detects | Investigates | Real finding |
|---|---|---|---|---|---|
| 1 | A01:2025 Broken Access Control | `scripts/scenario1-credential-misuse.sh` | `CreateAccessKeyFilter`, `template.yaml:416` | `prompts/scenario1.txt` | `findings/scenario1-credential-misuse-finding.md` |
| 2 | A02:2025 Security Misconfiguration | `scripts/scenario2-open-security-group.sh` | `OpenSecurityGroupFilter`, `template.yaml:427` | `prompts/scenario2.txt` | `findings/scenario2-open-security-group-finding.md` |
| 3 | A05:2025 Injection, A07:2025 Authentication Failures | `scripts/scenario3-api-abuse.sh` | `RejectedRequestFilter`, `template.yaml:441` | `prompts/scenario3.txt` | `findings/scenario3-api-abuse-finding.md` |
| 3 | A09:2025 Security Logging and Alerting Failures | the handler's `source_ip` lookup, `template.yaml:366` | not detected, this is the point | same prompt | same finding, Source Addresses section |
| 4 | A03:2025 Software Supply Chain Failures | not yet written, see below | | | |

Line numbers refer to `template.yaml` as committed. If you edit the template, re-check them.

## Scenario 4, A03:2025 Software Supply Chain Failures

Reserved and not yet implemented. Owner: Samir Behara (`samirbhr`).

A03:2025 is the one top-three category the lab does not cover, and it is the natural fourth scenario
because supply chain compromise produces exactly the kind of evidence this lab is about: an artifact
or dependency changed, and the question is whether anything downstream consumed it.

### The structure each scenario follows

Every scenario is four artifacts plus one template change. Mirror this and it will drop in.

1. **A generator**, `scripts/scenario4-<name>.sh`. Reads what it needs from stack outputs using the
   `out()` helper the other three scripts share, performs the activity, and prints what it did so the
   operator can see the evidence it should have produced. It must be safe to run in a sandbox and it
   must leave a trail that CloudTrail or an application log actually records.
2. **Evidence sources in `template.yaml`**, whatever the scenario needs to read later. Keep the
   `NamePrefix` parameter convention and the `LogRetentionDays` default so teardown stays clean.
3. **A metric filter and alarm** in `template.yaml`. Follow the deliberate bluntness of
   `RejectedRequestFilter`: the alarm should say that something changed, not name the category. If the
   filter pattern encodes the answer, the investigation has nothing to establish.
4. **A prompt template**, `prompts/scenario4.txt`. Use the `__PLACEHOLDER__` convention and add any new
   placeholder to the `sed` list in `scripts/render-prompts.sh`. Never commit real account identifiers;
   `prompts/rendered/` is gitignored for that reason.
5. **A finding**, `findings/scenario4-<name>-finding.md`, captured from a real run. Replace the account
   ID with `111122223333` and any real address with `203.0.113.42` before committing. Leave counts,
   timestamps and conclusions exactly as the agent produced them.

Then add a row to the table above and a line to the run block in `README.md`.

### One design note worth reading first

The other three scenarios all rest on evidence AWS records for you: CloudTrail management events, S3
data events, VPC Flow Logs, application logs. A supply chain scenario has no equivalent default. You
have to decide what the recorded evidence is before deciding what the attack is, otherwise the
investigation has nothing to read. Options that stay sandbox safe include a CodeArtifact or ECR
repository where a package or image version changes and CloudTrail records the push and the pulls, or
an S3 artifact bucket with data events enabled so the write and every subsequent read are attributable.
Both give the agent a real question to answer: who changed the artifact, and what consumed it after.

Deliberately avoid anything that needs a genuinely vulnerable dependency or outbound network access
from the lab. The value is in the evidence trail, not in real exploitation.

## A05:2025 Injection, end to end

This is the path to read if you are following how injection is wired through the lab. Note this was
labelled A03 under the 2021 list.

### 1. What generates the injection traffic

`scripts/scenario3-api-abuse.sh` sends a mixed burst. The injection payloads are:

```bash
SQLI=("' OR 1=1--" "1 UNION SELECT null,null--" "'; DROP TABLE payments--")
```

They go out as a query parameter on the login path, paired with a valid looking username so the
request is well formed:

```bash
curl -s -o /dev/null -w '%{http_code}' -G "$ENDPOINT/login" \
  --data-urlencode "username=admin" --data-urlencode "q=$p" --max-time 10
```

The loop selects by `i % 5`, so injection is one request in five. At the default `BURST=90` that is 18
injection attempts, 18 path traversal attempts, and 54 authentication failures. Override with
`BURST=<n>` if you want a different volume; the ratio holds.

Nothing is actually vulnerable. There is no database and no filesystem read. The payloads exist so the
handler can classify and reject them, which is what produces the evidence.

### 2. What classifies it server side

`template.yaml` line 338, in the payment API handler:

```python
SQLI = re.compile(r"(\bor\b\s+1=1|union\s+select|';|--\s|\bdrop\s+table\b)", re.I)
```

`classify()` checks `SQLI` first, then `TRAVERSAL`, and falls through to `authentication_failure`.
Order matters: an injection payload sent with a username would otherwise be counted as an auth
failure. Each request is rejected and one JSON line is emitted with `category`,
`outcome: "denied"`, and `http_status: 400` for injection and traversal, `401` for auth failures.

### 3. What detects it

Nothing detects injection specifically, and that is deliberate. `RejectedRequestFilter` at
`template.yaml:441` counts every rejected request:

```
{ $.event = "request_rejected" }
```

The alarm trips above 50 in five minutes. So the alarm reports that the rejection rate jumped, not
that someone attempted SQL injection. Splitting the burst into categories is the investigation's job.
A filter that matched `sql_injection_attempt` directly would hand the agent its own answer and the
scenario would demonstrate nothing.

### 4. What the agent found

From `findings/scenario3-api-abuse-finding.md`, on a real run:

- 90 requests over roughly 44 seconds
- 54 `authentication_failure` at 401, 18 `sql_injection_attempt` at 400, 18 `path_traversal_attempt`
  at 400
- zero succeeded, verified three independent ways, including that `session_issued` summed to 0
- all 90 records logged `source_ip` as the string `unknown`

The agent derived the category split from the logs, which is the A05:2025 half of the result, and then
reported that it could not attribute the traffic to any address, which is the A09:2025 half.

### 5. The A09:2025 finding inside scenario 3

`template.yaml` line 366 reads the wrong field for this API type:

```python
ident = ctx.get("identity", {})     # REST API (v1) shape
```

This is an HTTP API, so the caller address lives at `requestContext.http.sourceIp`. The lookup misses
on every request and `source_ip` is logged as `"unknown"` every time. The field is present and
populated, so the log looks complete while being unable to answer where the traffic came from.

That is left in on purpose and is commented as such in the template. It is a more representative
logging failure than an absent field, because an absent field is obvious in review and a field that is
always the same placeholder is not. To close the gap and see the contrast, change that one line to:

```python
ident = ctx.get("http", {})
```

Then rerun scenario 3 and the same prompt returns real addresses.

## Why scenario 3 carries three categories

An earlier outline mapped scenario 3 to the logging category alone. The traffic itself is injection and
credential stuffing, which are A05:2025 and A07:2025. A09:2025 describes the missing source address,
which is a property of the lab's logging rather than of the attack.

The distinction matters because the remediation differs. Injection and authentication failures are
addressed at the edge with input validation and rate limiting. A logging failure is addressed in the
application's logging code, and until it is fixed, no amount of correlation recovers the addresses
after the fact.

## Not covered

Once scenario 4 is written the lab covers six of the ten 2025 categories: Broken Access Control,
Security Misconfiguration, Software Supply Chain Failures, Injection, Authentication Failures, and
Security Logging and Alerting Failures.

It does not attempt Cryptographic Failures, Insecure Design, Software or Data Integrity Failures, or
Mishandling of Exceptional Conditions. Those need either a real cryptographic failure, a design level
argument rather than an evidence trail, or outbound network access from the lab. Each would make the lab
less safe to deploy in a sandbox than the value it adds to a triage demonstration.

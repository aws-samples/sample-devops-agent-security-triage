I now have a complete picture from both data sources. Here's the full forensic reconstruction:

───
*Forensic Reconstruction: `sectriage-demo-user` Activity*

*Account:* 111122223333 | *Region:* us-east-1 | *Source IP:* `203.0.113.42` (all calls) | *User Agent:* `aws-cli/1.45.55` on macOS arm64 | *Access Key Used:* `AKEXAMPLEKEYOSFODNN7`

───
*Complete API Call Timeline (44 calls in ~36 seconds)*

*Event Time (UTC)  API Call  Service  Result  Details*

1  02:38:10  `GetCallerIdentity`  sts  ✅ *SUCCESS*  Identity verification
2  02:38:11  `ListUsers`  iam  ✅ *SUCCESS*  Enumerated all IAM users
3  02:38:12  `ListAttachedUserPolicies`  iam  ✅ *SUCCESS*  Checked own attached policies
4  02:38:13  `CreateAccessKey`  iam  ✅ *SUCCESS*  *Created new key `AKEXAMPLEKEY44QH8DHB`*
5  02:38:14  `AttachUserPolicy`  iam  ❌ *ACCESS DENIED*  Privilege escalation blocked
6  02:38:15  `ListObjects`  s3  ✅ *SUCCESS*  Listed `customer-records/` prefix
7  02:38:25  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-12.json`
8  02:38:25  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-13.json`
9  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-19.json`
10  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-40.json`
11  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-32.json`
12  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-11.json`
13  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-22.json`
14  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-28.json`
15  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-04.json`
16  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-39.json`
17  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-16.json`
18  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-02.json`
19  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-29.json`
20  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-05.json`
21  02:38:31  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-31.json`
22  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-37.json`
23  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-01.json`
24  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-08.json`
25  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-10.json`
26  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-36.json`
27  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-24.json`
28  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-06.json`
29  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-25.json`
30  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-18.json`
31  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-14.json`
32  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-20.json`
33  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-33.json`
34  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-26.json`
35  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-23.json`
36  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-38.json`
37  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-07.json`
38  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-17.json`
39  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-35.json`
40  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-21.json`
41  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-15.json`
42  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-30.json`
43  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-27.json`
44  02:38:46  `GetObject`  s3  ✅ *SUCCESS*  `customer-records/customer-34.json`

───
*Summary Statistics*

Metric  Value

*Total API calls*  44
*Succeeded*  43
*Denied*  1 (`AttachUserPolicy` — AccessDenied)
*S3 objects read (GetObject)*  *38*
*Source IP*  `203.0.113.42` (single IP, all calls)
*Total duration*  ~36 seconds (02:38:10Z → 02:38:46Z)
*Target bucket*  `sectriage-lab-data-111122223333-us-east-1`
*Files exfiltrated*  `customer-records/customer-01.json` through `customer-40.json` (38 of 40)

───
*Attack Kill-Chain Interpretation*

Phase  MITRE Tactic  Actions

*1. Recon*  Discovery  `GetCallerIdentity` → `ListUsers` → `ListAttachedUserPolicies`
*2. Persistence*  Persistence  `CreateAccessKey` → new key *`AKEXAMPLEKEY44QH8DHB`* now active
*3. Priv-Esc (failed)*  Privilege Escalation  `AttachUserPolicy` → *DENIED*
*4. Exfiltration*  Collection + Exfiltration  `ListObjects` → 38× `GetObject` on customer PII

───
*Recommendations*

1. *Immediately deactivate both access keys* for `sectriage-demo-user`:
   • Original key: `AKEXAMPLEKEYOSFODNN7`
   • Newly-created persistence key: `AKEXAMPLEKEY44QH8DHB`
2. *Rotate or delete* the IAM user entirely if not needed.
3. *Assess data exposure* — 38 customer record files (each 209 bytes) were fully downloaded; evaluate PII content for breach notification obligations.
4. *Block source IP* `203.0.113.42` via WAF/SCPs if appropriate.
5. *Investigate credential provenance* — determine how the original access key `AKEXAMPLEKEYOSFODNN7` was compromised (code repo leak, phishing, metadata service exposure, etc.).

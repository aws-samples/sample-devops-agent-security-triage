I now have a complete characterization of the burst. Here's the full analysis:

───
*Summary*

A concentrated burst of *90 malicious requests* hit `payments-api` over a *~44-second window* (`2026-08-10 02:49:32 – 02:50:16 UTC`). All requests were *denied* — no request succeeded, and no sessions were issued.

*Time Window*

Metric  Value

First event  `2026-08-10 02:49:32.355 UTC`
Last event  `2026-08-10 02:50:16.355 UTC`
Duration  ~44 seconds
Total denied events  *90*

*Categories of Request*

Category  Count  HTTP Status  First Seen  Last Seen

`authentication_failure`  54  401  02:49:32.834  02:50:15.876
`sql_injection_attempt`  18  400  02:49:34.295  02:50:16.355
`path_traversal_attempt`  18  400  02:49:32.355  02:50:14.437

The attack is *mixed-vector* — credential stuffing/brute-force (60%) combined with injection and path-traversal probes (40%). All three categories ran concurrently throughout the burst, consistent with an automated scanning tool cycling through payloads.

*Source Addresses*

*All 90 events have `source_ip = "unknown"`.* The application logs do not record a usable source IP for these requests. The logs *cannot answer* what IP(s) originated this traffic. To identify sources you would need to consult an upstream access log (e.g., API Gateway, ALB, or CloudFront access logs).

*Usernames Targeted*

Username  Count

`admin`  27
`unknown`  18
`backup`  8
`test`  8
`root`  7
`finance`  6
`svc_payments`  6
`operator`  6
`jsmith`  4

The username list combines generic/default accounts (`admin`, `root`, `test`, `backup`) with accounts that appear environment-specific (`svc_payments`, `finance`, `operator`, `jsmith`). The `unknown` entries correspond to the `path_traversal_attempt` and `sql_injection_attempt` categories where no username was extracted.

*Did Any Request Succeed?*

*Explicitly NO.* I verified this three independent ways:
1. Querying for `outcome != 'denied'` with `ispresent(outcome)` → *0 records*
2. Querying for `session_issued = 1` → *0 records*
3. The `session_issued` sum across all 90 events is *0*

Every request in the log group during this window was denied. No authentication token or session was issued to the attacker.

*Path Targeted*

All 90 requests targeted the root path (`/`) exclusively.

*Limitations — What the Logs Cannot Answer*

• *Source IP attribution*: All events log `source_ip = "unknown"`, so we cannot determine whether this was a single-source or distributed attack from these logs alone.
• *Request payload detail*: The logs categorize the attack type but don't include the raw request body or headers.
• *Upstream context*: API Gateway or load balancer access logs would be needed to recover source IPs, user-agents, and geographic origin.

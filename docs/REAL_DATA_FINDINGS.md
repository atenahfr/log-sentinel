# Testing Log Sentinel on Real Traffic

I ran Log Sentinel on 10,000 lines of real Apache access logs
(elastic/examples `apache_logs`). Everything before this used synthetic
data I generated myself. The real log exposed problems the synthetic
data never could.

## What broke, and what I changed

| # | Problem found | Cause | Fix |
|---|---------------|-------|-----|
| 1 | Parser silently dropped 669 of 10,000 lines | Apache logs `-` instead of a number when a response has no body; my regex only allowed digits | Allow `-` and store it as 0 bytes. Now parses 10,000/10,000 |
| 2 | 404-spike rule flagged a search-engine crawler | The rule counted raw 404s and ignored what was requested | Count only 404s on sensitive paths (`/admin`, `/.env`, `/wp-login`, ...) |
| 3 | Off-hours rule flagged 6 hours of normal traffic | A fixed "midnight to 6am is suspicious" window; the site has visitors in every timezone and traffic was nearly flat (345-498 requests/hour) | Flag an hour only if it exceeds mean + 2 standard deviations |
| 4 | Report crashed when no anomalies were found | Empty results had no columns; only appeared once the false alarms were gone | Guard for the empty case |
| 5 | ML flagged 261 IPs (about 15%) | Isolation Forest was set to flag the top 15% by construction; many flagged IPs had 1-2 requests, so ratios like "share of traffic at night" were 0% or 100% from one data point | Ignore IPs with fewer than 5 requests. ML flags dropped to 95 |

## What I measured

- Rule-based detector on synthetic data: precision 1.0, recall 1.0 (unchanged by the fixes)
- ML detector on synthetic data: precision 0.857 -> 0.906, recall 1.0 -> 0.967
- Real log: rule-based alerts went from 2 false positives plus 6 flagged hours to 0

## What I can and can't claim

- "Zero alerts" on the real log is **not** proof the rules work. The file has
  no known attacks, so I can show the false alarms are gone, not that real
  attacks would be caught.
- The ML detector's 95 flags on real data are unverified. The top ones were
  search-engine crawlers and heavy browsers, and I can't confirm any are malicious.
- My sensitive-path list was chosen after reading one file. It can miss
  scanners that probe other paths and needs testing on more logs.
- One synthetic brute-force attacker (31 failed logins to `/login`) is missed
  by the ML. The rules catch it. I did not add a feature to fix it, because
  my synthetic attackers are my own invention and tuning to them would
  prove nothing about real attackers.

## Lesson

Scores on synthetic data tell you the code runs, not that the detector works.
The fixed 15% contamination, the night window and the raw 404 count all looked
fine on data I generated and failed on real traffic.

# SSH Attack Detection Report

- Failed logins parsed: **96**
- Successful logins parsed: **7**
- Unique source IPs with failures: **4**
- Alerts: **5**

## Alerts

| Severity | Rule | Source IP | Details |
|---|---|---|---|
| CRITICAL | R3 Compromise | 203.0.113.99 | Successful password login as 'deploy' at 21:02:29 after attack activity |
| HIGH | R1 Brute force | 203.0.113.45 | 60 failures (peak 60 in 5 min) against root |
| HIGH | R1 Brute force | 198.51.100.77 | 10 failures (peak 10 in 5 min) against admin, deploy, ftp, git, guest, oracle, postgres, test, ubuntu, user |
| HIGH | R2 Password spray | 198.51.100.77 | 10 distinct usernames tried: admin, deploy, ftp, git, guest, oracle, postgres, test, ubuntu, user |
| HIGH | R1 Brute force | 203.0.113.99 | 25 failures (peak 25 in 5 min) against deploy |

## Failures by Source IP

| IP | Failures |
|---|---|
| 203.0.113.45 | 60 |
| 203.0.113.99 | 25 |
| 198.51.100.77 | 10 |
| 192.0.2.25 | 1 |

## Recommended Response

1. Isolate web01 and disable the `deploy` account immediately.
2. Review `deploy` activity after the compromise (bash history, new keys in ~/.ssh/authorized_keys, cron jobs).
3. Block 203.0.113.45, 203.0.113.99 and 198.51.100.77 at the firewall.
4. Disable password authentication (`PasswordAuthentication no`) and enforce key-based login.
5. Deploy fail2ban or equivalent rate limiting.

_Note: 192.0.2.25 (user bob) had one failure followed by success; below threshold and treated as a normal typo._

# SSH Brute-Force & Password-Spray Detection Lab

A Python log analyzer that reads a Linux `auth.log`, detects SSH attacks, and flags the one attack that **succeeded**.

## Detection rules
| Rule | Logic | MITRE ATT&CK |
|---|---|---|
| R1 Brute force | 10+ failed logins from one IP within 5 minutes (sliding window) | T1110.001 |
| R2 Password spray | 5+ different usernames tried from one IP | T1110.003 |
| R3 Compromise | Successful login from an IP already flagged by R1/R2 (**CRITICAL**) | T1078 |

## Sample output
See [`sample_report.md`](sample_report.md) for the full report this lab produces.

## How to run
```bash
python3 generate_logs.py        # creates logs/auth.log (103 lines, synthetic)
python3 detect.py               # prints alerts, writes output/report.md
python3 detect.py /var/log/auth.log   # or point it at a real log
```
Python 3.8+ standard library only.

## Results
```
[CRITICAL] R3 Compromise 203.0.113.99: Successful password login as 'deploy' after attack activity
[HIGH] R1 Brute force 203.0.113.45: 60 failures against root
[HIGH] R2 Password spray 198.51.100.77: 10 distinct usernames tried
[HIGH] R1 Brute force 203.0.113.99: 25 failures against deploy
```
A normal user typo (1 failure then success) is correctly **not** flagged.

## Response recommendations
Isolate the host, disable the compromised account, review post-login activity, block attacker IPs, disable SSH password auth, and add fail2ban.

## Skills demonstrated
Log analysis · Threat detection · Regex parsing · Sliding-window detection · MITRE ATT&CK mapping · Incident response · Python

> All data is fictional. IPs are from RFC 5737 documentation ranges.

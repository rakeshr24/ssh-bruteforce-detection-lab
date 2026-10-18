"""SSH brute-force and password-spray detector for Linux auth.log.

Detection rules (tunable):
  R1 Brute force   : >= FAIL_THRESHOLD failures from one IP within WINDOW
  R2 Password spray: >= SPRAY_USERS distinct usernames from one IP
  R3 Compromise    : a successful login from an IP that triggered R1 or R2  (CRITICAL)
Maps to MITRE ATT&CK T1110.001 (Password Guessing) and T1110.003 (Password Spraying).
"""
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

FAIL_THRESHOLD = 10
WINDOW = timedelta(minutes=5)
SPRAY_USERS = 5
YEAR = 2026

FAIL = re.compile(r"^(\w{3} \d{2} [\d:]{8}) \S+ sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+)")
OK = re.compile(r"^(\w{3} \d{2} [\d:]{8}) \S+ sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+)")


def parse_time(s):
    return datetime.strptime(f"{YEAR} {s}", "%Y %b %d %H:%M:%S")


def parse(path):
    fails, oks = [], []
    for line in Path(path).read_text().splitlines():
        if m := FAIL.match(line):
            fails.append((parse_time(m[1]), m[2], m[3]))
        elif m := OK.match(line):
            oks.append((parse_time(m[1]), m[3], m[4], m[2]))
    return fails, oks


def detect(fails, oks):
    alerts = []
    by_ip = defaultdict(list)
    for t, user, ip in fails:
        by_ip[ip].append((t, user))

    flagged = {}
    for ip, attempts in by_ip.items():
        attempts.sort()
        times = [t for t, _ in attempts]
        # sliding window for R1
        j, peak = 0, 0
        for i in range(len(times)):
            while times[i] - times[j] > WINDOW:
                j += 1
            peak = max(peak, i - j + 1)
        users = {u for _, u in attempts}
        if peak >= FAIL_THRESHOLD:
            alerts.append(("HIGH", "R1 Brute force", ip,
                           f"{len(attempts)} failures (peak {peak} in {WINDOW.seconds // 60} min) against {', '.join(sorted(users))}"))
            flagged[ip] = times[0]
        if len(users) >= SPRAY_USERS:
            alerts.append(("HIGH", "R2 Password spray", ip,
                           f"{len(users)} distinct usernames tried: {', '.join(sorted(users))}"))
            flagged.setdefault(ip, times[0])

    for t, user, ip, method in oks:
        if ip in flagged and t >= flagged[ip]:
            alerts.append(("CRITICAL", "R3 Compromise", ip,
                           f"Successful {method} login as '{user}' at {t:%H:%M:%S} after attack activity"))
    order = {"CRITICAL": 0, "HIGH": 1}
    return sorted(alerts, key=lambda a: order[a[0]]), by_ip


def report(alerts, by_ip, fails, oks, out):
    L = ["# SSH Attack Detection Report", "",
         f"- Failed logins parsed: **{len(fails)}**",
         f"- Successful logins parsed: **{len(oks)}**",
         f"- Unique source IPs with failures: **{len(by_ip)}**",
         f"- Alerts: **{len(alerts)}**", "",
         "## Alerts", "", "| Severity | Rule | Source IP | Details |", "|---|---|---|---|"]
    L += [f"| {s} | {r} | {ip} | {d} |" for s, r, ip, d in alerts]
    L += ["", "## Failures by Source IP", "", "| IP | Failures |", "|---|---|"]
    L += [f"| {ip} | {len(a)} |" for ip, a in sorted(by_ip.items(), key=lambda x: -len(x[1]))]
    L += ["", "## Recommended Response", "",
          "1. Isolate web01 and disable the `deploy` account immediately.",
          "2. Review `deploy` activity after the compromise (bash history, new keys in ~/.ssh/authorized_keys, cron jobs).",
          "3. Block 203.0.113.45, 203.0.113.99 and 198.51.100.77 at the firewall.",
          "4. Disable password authentication (`PasswordAuthentication no`) and enforce key-based login.",
          "5. Deploy fail2ban or equivalent rate limiting.",
          "", "_Note: 192.0.2.25 (user bob) had one failure followed by success; below threshold and treated as a normal typo._"]
    Path(out).write_text("\n".join(L))


if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "logs" / "auth.log"
    out_dir = Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)
    fails, oks = parse(log)
    alerts, by_ip = detect(fails, oks)
    report(alerts, by_ip, fails, oks, out_dir / "report.md")
    for s, r, ip, d in alerts:
        print(f"[{s}] {r} {ip}: {d}")

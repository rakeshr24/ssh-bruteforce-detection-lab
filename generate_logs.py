"""Generate a synthetic Linux auth.log with normal traffic, a brute-force
attack, a password-spray attack, and one successful compromise.
All IPs are from documentation ranges (RFC 5737) and all data is fictional."""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent / "logs" / "auth.log"
OUT.parent.mkdir(exist_ok=True)
HOST = "web01"
start = datetime(2026, 10, 12, 0, 0, 0)
lines = []


def add(t, msg):
    lines.append((t, f"{t:%b %d %H:%M:%S} {HOST} sshd[{random.randint(1000, 9999)}]: {msg}"))


# Normal admin logins throughout the day
for h in [8, 9, 12, 14, 17]:
    t = start + timedelta(hours=h, minutes=random.randint(0, 50))
    add(t, f"Accepted publickey for alice from 192.0.2.10 port {random.randint(40000, 60000)} ssh2")

# Occasional typo by a real user
t = start + timedelta(hours=10, minutes=5)
add(t, "Failed password for bob from 192.0.2.25 port 51022 ssh2")
add(t + timedelta(seconds=8), "Accepted password for bob from 192.0.2.25 port 51030 ssh2")

# Brute force against root from one IP (fails)
t = start + timedelta(hours=2, minutes=13)
for _ in range(60):
    t += timedelta(seconds=random.uniform(0.5, 2.0))
    add(t, f"Failed password for root from 203.0.113.45 port {random.randint(30000, 65000)} ssh2")

# Password spray: many usernames, one IP
t = start + timedelta(hours=3, minutes=40)
for u in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "deploy", "ftp", "guest", "user"]:
    t += timedelta(seconds=random.uniform(3, 6))
    add(t, f"Failed password for invalid user {u} from 198.51.100.77 port {random.randint(30000, 65000)} ssh2")

# Brute force that SUCCEEDS (the incident)
t = start + timedelta(hours=21, minutes=2)
for _ in range(25):
    t += timedelta(seconds=random.uniform(0.8, 1.5))
    add(t, f"Failed password for deploy from 203.0.113.99 port {random.randint(30000, 65000)} ssh2")
t += timedelta(seconds=2)
add(t, "Accepted password for deploy from 203.0.113.99 port 48211 ssh2")

lines.sort(key=lambda x: x[0])
OUT.write_text("\n".join(l for _, l in lines) + "\n")
print(f"Wrote {len(lines)} log lines to {OUT}")

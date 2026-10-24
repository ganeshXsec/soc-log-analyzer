from collections import Counter
import re

LOG_FILE = "sample.log"
ALERT_THRESHOLD = 3

failed_ips = Counter()

print("=== SOC SECURITY LOG ANALYZER ===")

try:
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if "FAILED_LOGIN" in line:
                match = re.search(r"\bip=(\S+)", line)

                if match:
                    failed_ips[match.group(1)] += 1

    print("\nSecurity Alerts:")

    for ip, count in failed_ips.items():
        if count >= ALERT_THRESHOLD:
            print(f"[ALERT] {ip}: {count} failed login attempts")

    print("\nAnalysis complete.")

except FileNotFoundError:
    print("sample.log not found. Create it in this folder.")

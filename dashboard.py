import re
import matplotlib.pyplot as plt
from collections import Counter

log_file = "alerts.log"

ips = []

with open(log_file, "r") as file:
    for line in file:
        match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)

        if match:
            ips.append(match.group(1))

ip_counts = Counter(ips)

print("Intrusion Detection Report")
print("==========================")

for ip, count in ip_counts.items():
    print(f"{ip}: {count} alerts")

if ip_counts:
    plt.figure(figsize=(8, 5))
    plt.bar(ip_counts.keys(), ip_counts.values())

    plt.title("Network Intrusion Detection Alerts")
    plt.xlabel("Source IP Address")
    plt.ylabel("Number of Alerts")

    plt.xticks(rotation=30)
    plt.tight_layout()

    plt.savefig("intrusion_report.png")
    plt.show()

    print("\nGraph saved as intrusion_report.png")
else:
    print("No alerts found.")
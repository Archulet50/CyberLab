import re
from collections import Counter
from datetime import datetime

log_file = "/var/log/auth.log"
output_file = "/home/matteo/SOC-Lab/logs/detected_threats.log"
threshold = 3

events = []
users = []
ips = []

with open(log_file, "r") as file:
    for line in file:
        lower_line = line.lower()
        if (
            "authentication failure" in lower_line
            or "failed password" in lower_line
            or "invalid user" in lower_line
        ):
            events.append(line.strip())

            user_match = re.search(r"user=([A-Za-z0-9._-]+)", line)
            if user_match:
                users.append(user_match.group(1))

            ip_match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if ip_match:
                ips.append(ip_match.group(1))

user_counts = Counter(users)
ip_counts = Counter(ips)

with open(output_file, "a") as out:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out.write(f"\n===== Run at {current_time} =====\n")
    out.write("Detected authentication failures\n\n")

    out.write("Raw Events\n")
    for entry in events:
        out.write(entry + "\n")

    out.write("\nSummary by user\n")
    for user, count in user_counts.items():
        status = "HIGH" if count >= threshold else "REVIEW"
        out.write(f"{user}: {count} [{status}]\n")

    out.write("\nSummary by IP\n")
    for ip, count in ip_counts.items():
        status = "HIGH" if count >= threshold else "REVIEW"
        out.write(f"{ip}: {count} [{status}]\n")

print(f"\nDetected {len(events)} authentication failures")

print("\nSummary by user:")
for user, count in user_counts.items():
    status = "HIGH" if count >= threshold else "REVIEW"
    print(f"{user}: {count} [{status}]")

print("\nSummary by IP:")
for ip, count in ip_counts.items():
    status = "HIGH" if count >= threshold else "REVIEW"
    print(f"{ip}: {count} [{status}]")

print(f"\nSaved to {output_file}")

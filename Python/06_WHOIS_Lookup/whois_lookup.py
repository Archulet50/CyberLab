#################################################
# CyberLab
# Author: Matt Archuleta
# Project: WHOIS Lookup Tool
#################################################

import subprocess

print("=" * 45)
print("        CYBERLAB WHOIS LOOKUP")
print("=" * 45)

domain = input("Enter domain name: ")

print("\nRunning WHOIS lookup...\n")

try:
    result = subprocess.run(
        ["whois", domain],
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)
    else:
        print("No WHOIS data returned.")

except FileNotFoundError:
    print("WHOIS is not installed.")
    print("Install it with: sudo apt install whois")


#################################################
# CyberLab
# Author: Matt Archuleta
# Project: Subdomain Enumerator
#################################################

import socket

print("=" * 50)
print("        CYBERLAB SUBDOMAIN ENUMERATOR")
print("=" * 50)

domain = input("Enter domain name, example: example.com: ")

subdomains = [
    "www",
    "mail",
    "ftp",
    "dev",
    "test",
    "admin",
    "portal",
    "vpn",
    "api",
    "blog"
]

print("\nScanning subdomains...\n")

for sub in subdomains:
    target = f"{sub}.{domain}"

    try:
        ip = socket.gethostbyname(target)
        print(f"[+] Found: {target:<30} {ip}")
    except socket.gaierror:
        pass

print("\nScan complete.")

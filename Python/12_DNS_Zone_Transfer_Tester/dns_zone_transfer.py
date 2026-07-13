#!/usr/bin/env python3

import dns.query
import dns.zone
import dns.resolver

print("=" * 60)
print("CYBERLAB DNS ZONE TRANSFER TESTER")
print("=" * 60)

domain = input("Enter a domain (example: zonetransfer.me): ").strip()

try:
    nameservers = dns.resolver.resolve(domain, "NS")

    print("\nAuthoritative Name Servers:\n")

    for ns in nameservers:
        server = str(ns)

        print(f"Testing {server}")

        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(server, domain, timeout=5)
            )

            print("\n[!] WARNING")
            print("Zone Transfer SUCCESSFUL!")
            print("This server allows AXFR.\n")

            for name in zone.nodes.keys():
                print(name)

        except Exception:
            print("[+] Zone transfer refused (Secure)\n")

except Exception as e:
    print(f"\nError: {e}")

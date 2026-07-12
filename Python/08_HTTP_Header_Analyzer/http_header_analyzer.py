#!/usr/bin/env python3 

 

import urllib.request 

import urllib.error 

 

SECURITY_HEADERS = { 

    "Strict-Transport-Security": "Forces HTTPS", 

    "Content-Security-Policy": "Prevents code injection", 

    "X-Content-Type-Options": "Stops MIME sniffing", 

    "X-Frame-Options": "Helps prevent clickjacking", 

    "Referrer-Policy": "Controls referrer information", 

    "Permissions-Policy": "Restricts browser features", 

} 

 

print("=" * 60) 

print("           CYBERLAB HTTP HEADER ANALYZER") 

print("=" * 60) 

 

target = input("Enter website (example.com): ").strip() 

 

if not target.startswith(("http://", "https://")): 

    target = "https://" + target 

 

request = urllib.request.Request( 

    target, 

    headers={"User-Agent": "CyberLab/1.0"} 

) 

 

try: 

    with urllib.request.urlopen(request, timeout=10) as response: 

 

        print("\nStatus Code:", response.status) 

        print("Final URL:", response.geturl()) 

 

        print("\nHTTP Headers") 

        print("-" * 60) 

 

        for header, value in response.headers.items(): 

            print(f"{header}: {value}") 

 

        print("\nSecurity Header Check") 

        print("-" * 60) 

 

        found = 0 

 

        for header, description in SECURITY_HEADERS.items(): 

            if header in response.headers: 

                print(f"[+] {header}") 

                found += 1 

            else: 

                print(f"[-] {header}") 

 

            print(f"    {description}") 

 

        print("\nSummary") 

        print(f"{found}/{len(SECURITY_HEADERS)} security headers found.") 

 

except urllib.error.HTTPError as e: 

    print(f"HTTP Error: {e.code} - {e.reason}") 

 

except urllib.error.URLError as e: 

    print(f"Connection Error: {e.reason}") 

 

except Exception as e: 

    print(f"Unexpected Error: {e}") 

#!/usr/bin/env python3 

 

import ipaddress 

import re 

from pathlib import Path 

 

MD5_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$") 

SHA256_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$") 

DOMAIN_PATTERN = re.compile( 

    r"^(?=.{1,253}$)" 

    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+" 

    r"[A-Za-z]{2,63}$" 

) 

 

 

def classify_indicator(value: str) -> str | None: 

    try: 

        ipaddress.ip_address(value) 

        return "ip" 

    except ValueError: 

        pass 

 

    if SHA256_PATTERN.fullmatch(value): 

        return "sha256" 

 

    if MD5_PATTERN.fullmatch(value): 

        return "md5" 

 

    if DOMAIN_PATTERN.fullmatch(value): 

        return "domain" 

 

    return None 

 

 

def load_feed(feed_path: Path) -> dict[str, set[str]]: 

    indicators = { 

        "ip": set(), 

        "domain": set(), 

        "md5": set(), 

        "sha256": set(), 

        "unknown": set(), 

    } 

 

    with feed_path.open( 

        "r", 

        encoding="utf-8", 

        errors="ignore", 

    ) as feed_file: 

        for raw_line in feed_file: 

            value = raw_line.strip() 

 

            if not value or value.startswith("#"): 

                continue 

 

            indicator_type = classify_indicator(value) 

 

            if indicator_type: 

                indicators[indicator_type].add(value.lower()) 

            else: 

                indicators["unknown"].add(value) 

 

    return indicators 

 

 

def print_section(title: str, values: set[str]) -> None: 

    print(f"\n{title}") 

    print("-" * 60) 

 

    if not values: 

        print("None detected.") 

        return 

 

    for value in sorted(values): 

        print(value) 

 

 

print("=" * 60) 

print("     CYBERLAB THREAT INTELLIGENCE FEED PARSER") 

print("=" * 60) 

 

feed_input = input("Enter IOC feed [sample_ioc_feed.txt]: ").strip() 

feed_path = Path( 

    feed_input or "sample_ioc_feed.txt" 

).expanduser().resolve() 

 

if not feed_path.exists() or not feed_path.is_file(): 

    print("\n[!] IOC feed does not exist.") 

    raise SystemExit(1) 

 

try: 

    indicators = load_feed(feed_path) 

except (PermissionError, OSError) as error: 

    print(f"\n[!] Unable to read feed: {error}") 

    raise SystemExit(1) 

 

print("\nFeed Summary") 

print("-" * 60) 

print(f"Feed file       : {feed_path}") 

print(f"Unique IPs      : {len(indicators['ip'])}") 

print(f"Unique domains  : {len(indicators['domain'])}") 

print(f"Unique MD5s     : {len(indicators['md5'])}") 

print(f"Unique SHA-256s : {len(indicators['sha256'])}") 

print(f"Unknown entries : {len(indicators['unknown'])}") 

 

print_section("IP Indicators", indicators["ip"]) 

print_section("Domain Indicators", indicators["domain"]) 

print_section("MD5 Indicators", indicators["md5"]) 

print_section("SHA-256 Indicators", indicators["sha256"]) 

print_section("Unclassified Entries", indicators["unknown"]) 

 

output_path = Path("normalized_ioc_feed.csv").resolve() 

 

with output_path.open("w", encoding="utf-8") as output: 

    output.write("type,indicator\n") 

 

    for indicator_type in ("ip", "domain", "md5", "sha256"): 

        for value in sorted(indicators[indicator_type]): 

            output.write(f"{indicator_type},{value}\n") 

 

print("\n" + "-" * 60) 

print(f"Normalized feed saved to: {output_path}") 
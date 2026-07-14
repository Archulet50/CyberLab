#!/usr/bin/env python3 

 

import re 

from collections import Counter 

from pathlib import Path 

 

FAILURE_PATTERN = re.compile( 

    r"Failed password for (?:invalid user )?(?P<user>\S+) " 

    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})" 

) 

 

SUCCESS_PATTERN = re.compile( 

    r"Accepted (?:password|publickey) for (?P<user>\S+) " 

    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})" 

) 

 

BRUTE_FORCE_THRESHOLD = 3 

 

 

def analyze_log(log_path: Path) -> dict: 

    failed_ips = Counter() 

    failed_users = Counter() 

    successful_ips = Counter() 

    successful_users = Counter() 

    total_lines = 0 

 

    with log_path.open("r", encoding="utf-8", errors="ignore") as log_file: 

        for line in log_file: 

            total_lines += 1 

 

            failure_match = FAILURE_PATTERN.search(line) 

 

            if failure_match: 

                failed_ips[failure_match.group("ip")] += 1 

                failed_users[failure_match.group("user")] += 1 

                continue 

 

            success_match = SUCCESS_PATTERN.search(line) 

 

            if success_match: 

                successful_ips[success_match.group("ip")] += 1 

                successful_users[success_match.group("user")] += 1 

 

    suspicious_ips = { 

        ip: count 

        for ip, count in failed_ips.items() 

        if count >= BRUTE_FORCE_THRESHOLD 

    } 

 

    return { 

        "total_lines": total_lines, 

        "failed_ips": failed_ips, 

        "failed_users": failed_users, 

        "successful_ips": successful_ips, 

        "successful_users": successful_users, 

        "suspicious_ips": suspicious_ips, 

    } 

 

 

def print_counter(title: str, counter: Counter) -> None: 

    print(f"\n{title}") 

    print("-" * 60) 

 

    if not counter: 

        print("None detected.") 

        return 

 

    for item, count in counter.most_common(): 

        print(f"{item:<25} {count}") 

 

 

print("=" * 60) 

print("             CYBERLAB SOC LOG ANALYZER") 

print("=" * 60) 

 

log_input = input("Enter log file [sample_auth.log]: ").strip() 

log_path = Path(log_input or "sample_auth.log").expanduser().resolve() 

 

if not log_path.exists() or not log_path.is_file(): 

    print("\n[!] Log file does not exist.") 

    raise SystemExit(1) 

 

try: 

    results = analyze_log(log_path) 

except (PermissionError, OSError) as error: 

    print(f"\n[!] Unable to read log file: {error}") 

    raise SystemExit(1) 

 

print("\nAnalysis Summary") 

print("-" * 60) 

print(f"Log file              : {log_path}") 

print(f"Lines analyzed         : {results['total_lines']}") 

print(f"Failed login attempts  : {sum(results['failed_ips'].values())}") 

print(f"Successful logins      : {sum(results['successful_ips'].values())}") 

print(f"Brute-force threshold  : {BRUTE_FORCE_THRESHOLD}") 

 

print_counter("Failed Attempts by Source IP", results["failed_ips"]) 

print_counter("Failed Attempts by Username", results["failed_users"]) 

print_counter("Successful Logins by Source IP", results["successful_ips"]) 

 

print("\nPotential Brute-Force Sources") 

print("-" * 60) 

 

if results["suspicious_ips"]: 

    for ip, count in sorted( 

        results["suspicious_ips"].items(), 

        key=lambda item: item[1], 

        reverse=True, 

    ): 

        print(f"[HIGH] {ip:<20} {count} failed attempts") 

else: 

    print("[+] No source crossed the configured threshold.") 

 

report_path = Path("log_analysis_report.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab SOC Log Analysis Report\n") 

    report.write("=" * 60 + "\n") 

    report.write(f"Log file: {log_path}\n") 

    report.write(f"Lines analyzed: {results['total_lines']}\n") 

    report.write( 

        f"Failed login attempts: " 

        f"{sum(results['failed_ips'].values())}\n" 

    ) 

    report.write( 

        f"Successful logins: " 

        f"{sum(results['successful_ips'].values())}\n\n" 

    ) 

 

    report.write("Potential Brute-Force Sources\n") 

    report.write("-" * 60 + "\n") 

 

    if results["suspicious_ips"]: 

        for ip, count in sorted( 

            results["suspicious_ips"].items(), 

            key=lambda item: item[1], 

            reverse=True, 

        ): 

            report.write(f"{ip}: {count} failed attempts\n") 

    else: 

        report.write("None detected.\n") 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}") 
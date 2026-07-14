#!/usr/bin/env python3 

 

import re 

from collections import Counter 

from pathlib import Path 

 

FAILED_LOGIN = re.compile( 

    r"4625 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

SUCCESS_LOGIN = re.compile( 

    r"4624 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

ACCOUNT_LOCKOUT = re.compile( 

    r"4740 User:(?P<user>\S+)" 

) 

 

BRUTE_FORCE_THRESHOLD = 3 

 

 

def analyze_log(log_path: Path) -> dict: 

    failed_users = Counter() 

    failed_ips = Counter() 

    successful_users = Counter() 

    successful_ips = Counter() 

    lockout_users = Counter() 

    total_lines = 0 

 

    with log_path.open("r", encoding="utf-8", errors="ignore") as log_file: 

        for line in log_file: 

            total_lines += 1 

 

            failed = FAILED_LOGIN.search(line) 

            if failed: 

                failed_users[failed.group("user")] += 1 

                failed_ips[failed.group("ip")] += 1 

                continue 

 

            success = SUCCESS_LOGIN.search(line) 

            if success: 

                successful_users[success.group("user")] += 1 

                successful_ips[success.group("ip")] += 1 

                continue 

 

            lockout = ACCOUNT_LOCKOUT.search(line) 

            if lockout: 

                lockout_users[lockout.group("user")] += 1 

 

    suspicious_sources = { 

        ip: count 

        for ip, count in failed_ips.items() 

        if count >= BRUTE_FORCE_THRESHOLD 

    } 

 

    return { 

        "total_lines": total_lines, 

        "failed_users": failed_users, 

        "failed_ips": failed_ips, 

        "successful_users": successful_users, 

        "successful_ips": successful_ips, 

        "lockout_users": lockout_users, 

        "suspicious_sources": suspicious_sources, 

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

print("      CYBERLAB WINDOWS EVENT LOG ANALYZER") 

print("=" * 60) 

 

log_input = input("Enter log file [sample_security.log]: ").strip() 

log_path = Path(log_input or "sample_security.log").expanduser().resolve() 

 

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

print(f"Log file             : {log_path}") 

print(f"Lines analyzed        : {results['total_lines']}") 

print(f"Failed login attempts : {sum(results['failed_ips'].values())}") 

print(f"Successful logins     : {sum(results['successful_ips'].values())}") 

print(f"Account lockouts      : {sum(results['lockout_users'].values())}") 

print(f"Brute-force threshold : {BRUTE_FORCE_THRESHOLD}") 

 

print_counter("Failed Attempts by Source IP", results["failed_ips"]) 

print_counter("Failed Attempts by Username", results["failed_users"]) 

print_counter("Successful Logins by Source IP", results["successful_ips"]) 

print_counter("Account Lockouts by Username", results["lockout_users"]) 

 

print("\nPotential Brute-Force Sources") 

print("-" * 60) 

 

if results["suspicious_sources"]: 

    for ip, count in sorted( 

        results["suspicious_sources"].items(), 

        key=lambda item: item[1], 

        reverse=True, 

    ): 

        print(f"[HIGH] {ip:<20} {count} failed attempts") 

else: 

    print("[+] No source crossed the configured threshold.") 

 

report_path = Path("windows_event_log_report.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab Windows Event Log Analysis Report\n") 

    report.write("=" * 60 + "\n") 

    report.write(f"Log file: {log_path}\n") 

    report.write(f"Lines analyzed: {results['total_lines']}\n") 

    report.write( 

        f"Failed login attempts: " 

        f"{sum(results['failed_ips'].values())}\n" 

    ) 

    report.write( 

        f"Successful logins: " 

        f"{sum(results['successful_ips'].values())}\n" 

    ) 

    report.write( 

        f"Account lockouts: " 

        f"{sum(results['lockout_users'].values())}\n\n" 

    ) 

 

    report.write("Potential Brute-Force Sources\n") 

    report.write("-" * 60 + "\n") 

 

    if results["suspicious_sources"]: 

        for ip, count in sorted( 

            results["suspicious_sources"].items(), 

            key=lambda item: item[1], 

            reverse=True, 

        ): 

            report.write(f"{ip}: {count} failed attempts\n") 

    else: 

        report.write("None detected.\n") 

 

print("\n" + "-" * 60) 

#!/usr/bin/env python3 

 

import re 

from collections import Counter 

from pathlib import Path 

 

FAILED_LOGIN = re.compile( 

    r"4625 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

SUCCESS_LOGIN = re.compile( 

    r"4624 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

ACCOUNT_LOCKOUT = re.compile( 

    r"4740 User:(?P<user>\S+)" 

) 

 

BRUTE_FORCE_THRESHOLD = 3 

 

 

def analyze_log(log_path: Path) -> dict: 

    failed_users = Counter() 

    failed_ips = Counter() 

    successful_users = Counter() 

    successful_ips = Counter() 

    lockout_users = Counter() 

    total_lines = 0 

 

    with log_path.open("r", encoding="utf-8", errors="ignore") as log_file: 

        for line in log_file: 

            total_lines += 1 

 

            failed = FAILED_LOGIN.search(line) 

            if failed: 

                failed_users[failed.group("user")] += 1 

                failed_ips[failed.group("ip")] += 1 

                continue 

 

            success = SUCCESS_LOGIN.search(line) 

            if success: 

                successful_users[success.group("user")] += 1 

                successful_ips[success.group("ip")] += 1 

                continue 

 

            lockout = ACCOUNT_LOCKOUT.search(line) 

            if lockout: 

                lockout_users[lockout.group("user")] += 1 

 

    suspicious_sources = { 

        ip: count 

        for ip, count in failed_ips.items() 

        if count >= BRUTE_FORCE_THRESHOLD 

    } 

 

    return { 

        "total_lines": total_lines, 

        "failed_users": failed_users, 

        "failed_ips": failed_ips, 

        "successful_users": successful_users, 

        "successful_ips": successful_ips, 

        "lockout_users": lockout_users, 

        "suspicious_sources": suspicious_sources, 

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

print("      CYBERLAB WINDOWS EVENT LOG ANALYZER") 

print("=" * 60) 

 

log_input = input("Enter log file [sample_security.log]: ").strip() 

log_path = Path(log_input or "sample_security.log").expanduser().resolve() 

 

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

print(f"Log file             : {log_path}") 

print(f"Lines analyzed        : {results['total_lines']}") 

print(f"Failed login attempts : {sum(results['failed_ips'].values())}") 

print(f"Successful logins     : {sum(results['successful_ips'].values())}") 

print(f"Account lockouts      : {sum(results['lockout_users'].values())}") 

print(f"Brute-force threshold : {BRUTE_FORCE_THRESHOLD}") 

 

print_counter("Failed Attempts by Source IP", results["failed_ips"]) 

print_counter("Failed Attempts by Username", results["failed_users"]) 

print_counter("Successful Logins by Source IP", results["successful_ips"]) 

print_counter("Account Lockouts by Username", results["lockout_users"]) 

 

print("\nPotential Brute-Force Sources") 

print("-" * 60) 

 

if results["suspicious_sources"]: 

    for ip, count in sorted( 

        results["suspicious_sources"].items(), 

        key=lambda item: item[1], 

        reverse=True, 

    ): 

        print(f"[HIGH] {ip:<20} {count} failed attempts") 

else: 

    print("[+] No source crossed the configured threshold.") 

 

report_path = Path("windows_event_log_report.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab Windows Event Log Analysis Report\n") 

    report.write("=" * 60 + "\n") 

    report.write(f"Log file: {log_path}\n") 

    report.write(f"Lines analyzed: {results['total_lines']}\n") 

    report.write( 

        f"Failed login attempts: " 

        f"{sum(results['failed_ips'].values())}\n" 

    ) 

    report.write( 

        f"Successful logins: " 

        f"{sum(results['successful_ips'].values())}\n" 

    ) 

    report.write( 

        f"Account lockouts: " 

        f"{sum(results['lockout_users'].values())}\n\n" 

    ) 

 

    report.write("Potential Brute-Force Sources\n") 

    report.write("-" * 60 + "\n") 

 

    if results["suspicious_sources"]: 

        for ip, count in sorted( 

            results["suspicious_sources"].items(), 

            key=lambda item: item[1], 

            reverse=True, 

        ): 

            report.write(f"{ip}: {count} failed attempts\n") 

    else: 

        report.write("None detected.\n") 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}")#!/usr/bin/env python3 

 

import re 

from collections import Counter 

from pathlib import Path 

 

FAILED_LOGIN = re.compile( 

    r"4625 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

SUCCESS_LOGIN = re.compile( 

    r"4624 User:(?P<user>\S+) SourceIP:(?P<ip>\S+)" 

) 

 

ACCOUNT_LOCKOUT = re.compile( 

    r"4740 User:(?P<user>\S+)" 

) 

 

BRUTE_FORCE_THRESHOLD = 3 

 

 

def analyze_log(log_path: Path) -> dict: 

    failed_users = Counter() 

    failed_ips = Counter() 

    successful_users = Counter() 

    successful_ips = Counter() 

    lockout_users = Counter() 

    total_lines = 0 

 

    with log_path.open("r", encoding="utf-8", errors="ignore") as log_file: 

        for line in log_file: 

            total_lines += 1 

 

            failed = FAILED_LOGIN.search(line) 

            if failed: 

                failed_users[failed.group("user")] += 1 

                failed_ips[failed.group("ip")] += 1 

                continue 

 

            success = SUCCESS_LOGIN.search(line) 

            if success: 

                successful_users[success.group("user")] += 1 

                successful_ips[success.group("ip")] += 1 

                continue 

 

            lockout = ACCOUNT_LOCKOUT.search(line) 

            if lockout: 

                lockout_users[lockout.group("user")] += 1 

 

    suspicious_sources = { 

        ip: count 

        for ip, count in failed_ips.items() 

        if count >= BRUTE_FORCE_THRESHOLD 

    } 

 

    return { 

        "total_lines": total_lines, 

        "failed_users": failed_users, 

        "failed_ips": failed_ips, 

        "successful_users": successful_users, 

        "successful_ips": successful_ips, 

        "lockout_users": lockout_users, 

        "suspicious_sources": suspicious_sources, 

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

print("      CYBERLAB WINDOWS EVENT LOG ANALYZER") 

print("=" * 60) 

 

log_input = input("Enter log file [sample_security.log]: ").strip() 

log_path = Path(log_input or "sample_security.log").expanduser().resolve() 

 

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

print(f"Log file             : {log_path}") 

print(f"Lines analyzed        : {results['total_lines']}") 

print(f"Failed login attempts : {sum(results['failed_ips'].values())}") 

print(f"Successful logins     : {sum(results['successful_ips'].values())}") 

print(f"Account lockouts      : {sum(results['lockout_users'].values())}") 

print(f"Brute-force threshold : {BRUTE_FORCE_THRESHOLD}") 

 

print_counter("Failed Attempts by Source IP", results["failed_ips"]) 

print_counter("Failed Attempts by Username", results["failed_users"]) 

print_counter("Successful Logins by Source IP", results["successful_ips"]) 

print_counter("Account Lockouts by Username", results["lockout_users"]) 

 

print("\nPotential Brute-Force Sources") 

print("-" * 60) 

 

if results["suspicious_sources"]: 

    for ip, count in sorted( 

        results["suspicious_sources"].items(), 

        key=lambda item: item[1], 

        reverse=True, 

    ): 

        print(f"[HIGH] {ip:<20} {count} failed attempts") 

else: 

    print("[+] No source crossed the configured threshold.") 

 

report_path = Path("windows_event_log_report.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab Windows Event Log Analysis Report\n") 

    report.write("=" * 60 + "\n") 

    report.write(f"Log file: {log_path}\n") 

    report.write(f"Lines analyzed: {results['total_lines']}\n") 

    report.write( 

        f"Failed login attempts: " 

        f"{sum(results['failed_ips'].values())}\n" 

    ) 

    report.write( 

        f"Successful logins: " 

        f"{sum(results['successful_ips'].values())}\n" 

    ) 

    report.write( 

        f"Account lockouts: " 

        f"{sum(results['lockout_users'].values())}\n\n" 

    ) 

 

    report.write("Potential Brute-Force Sources\n") 

    report.write("-" * 60 + "\n") 

 

    if results["suspicious_sources"]: 

        for ip, count in sorted( 

            results["suspicious_sources"].items(), 

            key=lambda item: item[1], 

            reverse=True, 

        ): 

            report.write(f"{ip}: {count} failed attempts\n") 

    else: 

        report.write("None detected.\n") 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}") 
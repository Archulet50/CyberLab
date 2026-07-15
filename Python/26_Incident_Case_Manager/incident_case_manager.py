#!/usr/bin/env python3 

 

import csv 

from collections import Counter 

from pathlib import Path 

 

SEVERITY_RANK = { 

    "LOW": 1, 

    "MEDIUM": 2, 

    "HIGH": 3, 

    "CRITICAL": 4, 

} 

 

STATUS_ORDER = { 

    "OPEN": 1, 

    "INVESTIGATING": 2, 

    "CONTAINED": 3, 

    "CLOSED": 4, 

} 

 

 

print("=" * 60) 

print("          CYBERLAB INCIDENT CASE MANAGER") 

print("=" * 60) 

 

input_file = input( 

    "Enter case file [sample_cases.txt]: " 

).strip() 

 

case_path = Path( 

    input_file or "sample_cases.txt" 

).expanduser().resolve() 

 

if not case_path.exists() or not case_path.is_file(): 

    print("\n[!] Case file does not exist.") 

    raise SystemExit(1) 

 

cases = [] 

 

with case_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as case_file: 

    for line_number, raw_line in enumerate(case_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 5: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        case_date, case_id, title, severity, status = parts 

 

        severity = severity.upper() 

        status = status.upper() 

 

        cases.append( 

            { 

                "date": case_date, 

                "case_id": case_id, 

                "title": title, 

                "severity": severity, 

                "status": status, 

                "severity_rank": SEVERITY_RANK.get(severity, 0), 

                "status_rank": STATUS_ORDER.get(status, 99), 

            } 

        ) 

 

cases.sort( 

    key=lambda item: ( 

        -item["severity_rank"], 

        item["status_rank"], 

        item["case_id"], 

    ) 

) 

 

severity_counts = Counter(case["severity"] for case in cases) 

status_counts = Counter(case["status"] for case in cases) 

 

print("\nCase Summary") 

print("-" * 60) 

print(f"Total cases    : {len(cases)}") 

print(f"Critical       : {severity_counts['CRITICAL']}") 

print(f"High           : {severity_counts['HIGH']}") 

print(f"Medium         : {severity_counts['MEDIUM']}") 

print(f"Low            : {severity_counts['LOW']}") 

 

print("\nCase Status") 

print("-" * 60) 

print(f"Open           : {status_counts['OPEN']}") 

print(f"Investigating  : {status_counts['INVESTIGATING']}") 

print(f"Contained      : {status_counts['CONTAINED']}") 

print(f"Closed         : {status_counts['CLOSED']}") 

 

print("\nPrioritized Cases") 

print("-" * 60) 

 

for case in cases: 

    print( 

        f"[{case['severity']}] " 

        f"{case['case_id']} - {case['title']}" 

    ) 

    print(f"Date   : {case['date']}") 

    print(f"Status : {case['status']}") 

    print() 

 

open_cases = [ 

    case for case in cases 

    if case["status"] != "CLOSED" 

] 

 

print("Active Case Queue") 

print("-" * 60) 

 

if open_cases: 

    for case in open_cases: 

        print( 

            f"{case['case_id']:<12} " 

            f"{case['severity']:<10} " 

            f"{case['status']:<15} " 

            f"{case['title']}" 

        ) 

else: 

    print("No active cases.") 

 

text_report_path = Path("incident_case_report.txt").resolve() 

csv_report_path = Path("incident_case_report.csv").resolve() 

 

with text_report_path.open( 

    "w", 

    encoding="utf-8", 

) as report: 

    report.write("CyberLab Incident Case Report\n") 

    report.write("=" * 60 + "\n\n") 

 

    report.write("Case Summary\n") 

    report.write("-" * 60 + "\n") 

    report.write(f"Total cases: {len(cases)}\n") 

    report.write(f"Critical: {severity_counts['CRITICAL']}\n") 

    report.write(f"High: {severity_counts['HIGH']}\n") 

    report.write(f"Medium: {severity_counts['MEDIUM']}\n") 

    report.write(f"Low: {severity_counts['LOW']}\n\n") 

 

    report.write("Active Cases\n") 

    report.write("-" * 60 + "\n") 

 

    if open_cases: 

        for case in open_cases: 

            report.write( 

                f"{case['case_id']} | " 

                f"{case['severity']} | " 

                f"{case['status']} | " 

                f"{case['title']}\n" 

            ) 

    else: 

        report.write("No active cases.\n") 

 

with csv_report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "date", 

            "case_id", 

            "title", 

            "severity", 

            "status", 

        ], 

    ) 

 

    writer.writeheader() 

 

    for case in cases: 

        writer.writerow( 

            { 

                "date": case["date"], 

                "case_id": case["case_id"], 

                "title": case["title"], 

                "severity": case["severity"], 

                "status": case["status"], 

            } 

        ) 

 

print("\n" + "-" * 60) 

print(f"Text report saved to: {text_report_path}") 

print(f"CSV report saved to : {csv_report_path}") 
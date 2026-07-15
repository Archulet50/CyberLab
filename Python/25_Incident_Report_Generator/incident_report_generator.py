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

 

 

print("=" * 60) 

print("        CYBERLAB INCIDENT REPORT GENERATOR") 

print("=" * 60) 

 

input_file = input( 

    "Enter incident file [sample_incidents.txt]: " 

).strip() 

 

incident_path = Path( 

    input_file or "sample_incidents.txt" 

).expanduser().resolve() 

 

if not incident_path.exists() or not incident_path.is_file(): 

    print("\n[!] Incident file does not exist.") 

    raise SystemExit(1) 

 

incidents = [] 

 

with incident_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as incident_file: 

    for line_number, raw_line in enumerate(incident_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 4: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        incident_date, alert_name, severity, asset = parts 

        severity = severity.upper() 

 

        incidents.append( 

            { 

                "date": incident_date, 

                "alert_name": alert_name, 

                "severity": severity, 

                "asset": asset, 

                "severity_rank": SEVERITY_RANK.get(severity, 0), 

            } 

        ) 

 

incidents.sort( 

    key=lambda item: item["severity_rank"], 

    reverse=True, 

) 

 

severity_counts = Counter( 

    incident["severity"] 

    for incident in incidents 

) 

 

print("\nIncident Summary") 

print("-" * 60) 

print(f"Total incidents : {len(incidents)}") 

print(f"Critical        : {severity_counts['CRITICAL']}") 

print(f"High            : {severity_counts['HIGH']}") 

print(f"Medium          : {severity_counts['MEDIUM']}") 

print(f"Low             : {severity_counts['LOW']}") 

 

print("\nPrioritized Incidents") 

print("-" * 60) 

 

for incident in incidents: 

    print( 

        f"[{incident['severity']}] " 

        f"{incident['alert_name']}" 

    ) 

    print(f"Date  : {incident['date']}") 

    print(f"Asset : {incident['asset']}") 

    print() 

 

text_report_path = Path("incident_report.txt").resolve() 

csv_report_path = Path("incident_report.csv").resolve() 

 

with text_report_path.open( 

    "w", 

    encoding="utf-8", 

) as report: 

    report.write("CyberLab Incident Report\n") 

    report.write("=" * 60 + "\n\n") 

 

    report.write("Executive Summary\n") 

    report.write("-" * 60 + "\n") 

    report.write(f"Total incidents: {len(incidents)}\n") 

    report.write(f"Critical: {severity_counts['CRITICAL']}\n") 

    report.write(f"High: {severity_counts['HIGH']}\n") 

    report.write(f"Medium: {severity_counts['MEDIUM']}\n") 

    report.write(f"Low: {severity_counts['LOW']}\n\n") 

 

    report.write("Incident Details\n") 

    report.write("-" * 60 + "\n") 

 

    for incident in incidents: 

        report.write( 

            f"[{incident['severity']}] " 

            f"{incident['alert_name']}\n" 

        ) 

        report.write(f"Date: {incident['date']}\n") 

        report.write(f"Asset: {incident['asset']}\n\n") 

 

with csv_report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "date", 

            "alert_name", 

            "severity", 

            "asset", 

        ], 

    ) 

 

    writer.writeheader() 

 

    for incident in incidents: 

        writer.writerow( 

            { 

                "date": incident["date"], 

                "alert_name": incident["alert_name"], 

                "severity": incident["severity"], 

                "asset": incident["asset"], 

            } 

        ) 

 

print("-" * 60) 

print(f"Text report saved to: {text_report_path}") 

print(f"CSV report saved to : {csv_report_path}") 
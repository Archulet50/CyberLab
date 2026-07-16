#!/usr/bin/env python3 

 

import csv 

from collections import Counter 

from datetime import datetime 

from pathlib import Path 

 

TIME_FORMAT = "%Y-%m-%d %H:%M:%S" 

 

SEVERITY_WEIGHT = { 

    "LOW": 1, 

    "MEDIUM": 2, 

    "HIGH": 3, 

    "CRITICAL": 4, 

} 

 

STATUS_WEIGHT = { 

    "CLOSED": 0, 

    "CONTAINED": 1, 

    "INVESTIGATING": 2, 

    "OPEN": 3, 

} 

 

 

def calculate_score(severity: str, status: str) -> int: 

    return ( 

        SEVERITY_WEIGHT.get(severity, 1) * 10 

        + STATUS_WEIGHT.get(status, 0) * 3 

    ) 

 

 

print("=" * 72) 

print("                  CYBERLAB MINI SIEM DASHBOARD") 

print("=" * 72) 

 

input_file = input( 

    "Enter SIEM event file [sample_siem_events.txt]: " 

).strip() 

 

event_path = Path( 

    input_file or "sample_siem_events.txt" 

).expanduser().resolve() 

 

if not event_path.exists() or not event_path.is_file(): 

    print("\n[!] SIEM event file does not exist.") 

    raise SystemExit(1) 

 

events = [] 

 

with event_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as event_file: 

    for line_number, raw_line in enumerate(event_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 6: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        ( 

            timestamp_text, 

            alert_name, 

            severity, 

            mitre_technique, 

            source, 

            status, 

        ) = parts 

 

        try: 

            timestamp = datetime.strptime(timestamp_text, TIME_FORMAT) 

        except ValueError: 

            print( 

                f"[!] Invalid timestamp on line " 

                f"{line_number}: {timestamp_text}" 

            ) 

            continue 

 

        severity = severity.upper() 

        status = status.upper() 

 

        events.append( 

            { 

                "timestamp": timestamp, 

                "alert_name": alert_name, 

                "severity": severity, 

                "mitre_technique": mitre_technique, 

                "source": source, 

                "status": status, 

                "score": calculate_score(severity, status), 

            } 

        ) 

 

events.sort( 

    key=lambda item: ( 

        item["score"], 

        item["timestamp"], 

    ), 

    reverse=True, 

) 

 

severity_counts = Counter(event["severity"] for event in events) 

status_counts = Counter(event["status"] for event in events) 

mitre_counts = Counter(event["mitre_technique"] for event in events) 

 

print("\nDashboard Summary") 

print("-" * 72) 

print(f"Total alerts     : {len(events)}") 

print(f"Critical alerts  : {severity_counts['CRITICAL']}") 

print(f"High alerts      : {severity_counts['HIGH']}") 

print(f"Medium alerts    : {severity_counts['MEDIUM']}") 

print(f"Low alerts       : {severity_counts['LOW']}") 

print(f"Open cases       : {status_counts['OPEN']}") 

print(f"Investigating    : {status_counts['INVESTIGATING']}") 

print(f"Contained        : {status_counts['CONTAINED']}") 

print(f"Closed           : {status_counts['CLOSED']}") 

 

print("\nTop Prioritized Alerts") 

print("-" * 72) 

 

for event in events: 

    print( 

        f"[{event['severity']:<8}] " 

        f"{event['alert_name']:<30} " 

        f"Score: {event['score']}" 

    ) 

    print( 

        f"Time   : {event['timestamp'].strftime(TIME_FORMAT)}" 

    ) 

    print( 

        f"Source : {event['source']}" 

    ) 

    print( 

        f"MITRE  : {event['mitre_technique']}" 

    ) 

    print( 

        f"Status : {event['status']}" 

    ) 

    print() 

 

print("MITRE ATT&CK Activity") 

print("-" * 72) 

 

for technique, count in mitre_counts.most_common(): 

    print(f"{technique:<15} {count}") 

 

csv_report_path = Path("mini_siem_dashboard_report.csv").resolve() 

text_report_path = Path("mini_siem_dashboard_report.txt").resolve() 

 

with csv_report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "timestamp", 

            "alert_name", 

            "severity", 

            "mitre_technique", 

            "source", 

            "status", 

            "score", 

        ], 

    ) 

 

    writer.writeheader() 

 

    for event in events: 

        writer.writerow( 

            { 

                "timestamp": event["timestamp"].strftime(TIME_FORMAT), 

                "alert_name": event["alert_name"], 

                "severity": event["severity"], 

                "mitre_technique": event["mitre_technique"], 

                "source": event["source"], 

                "status": event["status"], 

                "score": event["score"], 

            } 

        ) 

 

with text_report_path.open( 

    "w", 

    encoding="utf-8", 

) as report: 

    report.write("CyberLab Mini SIEM Dashboard Report\n") 

    report.write("=" * 72 + "\n\n") 

 

    report.write("Dashboard Summary\n") 

    report.write("-" * 72 + "\n") 

    report.write(f"Total alerts: {len(events)}\n") 

    report.write(f"Critical alerts: {severity_counts['CRITICAL']}\n") 

    report.write(f"High alerts: {severity_counts['HIGH']}\n") 

    report.write(f"Medium alerts: {severity_counts['MEDIUM']}\n") 

    report.write(f"Low alerts: {severity_counts['LOW']}\n") 

    report.write(f"Open cases: {status_counts['OPEN']}\n") 

    report.write( 

        f"Investigating: {status_counts['INVESTIGATING']}\n" 

    ) 

    report.write(f"Contained: {status_counts['CONTAINED']}\n") 

    report.write(f"Closed: {status_counts['CLOSED']}\n\n") 

 

    report.write("Prioritized Alerts\n") 

    report.write("-" * 72 + "\n") 

 

    for event in events: 

        report.write( 

            f"[{event['severity']}] " 

            f"{event['alert_name']} | " 

            f"{event['source']} | " 

            f"{event['mitre_technique']} | " 

            f"{event['status']} | " 

            f"Score {event['score']}\n" 

        ) 

 

print("\n" + "-" * 72) 

print(f"CSV report saved to : {csv_report_path}") 

print(f"Text report saved to: {text_report_path}") 
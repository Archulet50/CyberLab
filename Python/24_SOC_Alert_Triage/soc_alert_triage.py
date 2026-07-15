#!/usr/bin/env python3 

 

import csv 

from pathlib import Path 

 

SEVERITY_WEIGHT = { 

    "LOW": 1, 

    "MEDIUM": 2, 

    "HIGH": 3, 

    "CRITICAL": 4, 

} 

 

 

def calculate_triage_score( 

    severity: str, 

    confidence: int, 

    event_count: int, 

) -> float: 

    severity_weight = SEVERITY_WEIGHT.get(severity.upper(), 1) 

 

    confidence_score = confidence / 10 

 

    volume_score = min(event_count, 20) / 2 

 

    return round( 

        severity_weight * 10 

        + confidence_score 

        + volume_score, 

        2, 

    ) 

 

 

def determine_priority(score: float) -> str: 

    if score >= 50: 

        return "P1" 

    if score >= 40: 

        return "P2" 

    if score >= 30: 

        return "P3" 

    return "P4" 

 

 

print("=" * 60) 

print("            CYBERLAB SOC ALERT TRIAGE") 

print("=" * 60) 

 

input_file = input( 

    "Enter alert file [sample_alerts.txt]: " 

).strip() 

 

alert_path = Path( 

    input_file or "sample_alerts.txt" 

).expanduser().resolve() 

 

if not alert_path.exists() or not alert_path.is_file(): 

    print("\n[!] Alert file does not exist.") 

    raise SystemExit(1) 

 

results = [] 

 

with alert_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as alert_file: 

    for line_number, raw_line in enumerate(alert_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 4: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        alert_name, severity, confidence_text, event_count_text = parts 

 

        try: 

            confidence = int(confidence_text) 

            event_count = int(event_count_text) 

        except ValueError: 

            print( 

                f"[!] Invalid numeric value on line " 

                f"{line_number}: {line}" 

            ) 

            continue 

 

        if confidence < 0 or confidence > 100: 

            print( 

                f"[!] Confidence must be 0-100 on line " 

                f"{line_number}" 

            ) 

            continue 

 

        severity = severity.upper() 

 

        triage_score = calculate_triage_score( 

            severity, 

            confidence, 

            event_count, 

        ) 

 

        priority = determine_priority(triage_score) 

 

        results.append( 

            { 

                "alert_name": alert_name, 

                "severity": severity, 

                "confidence": confidence, 

                "event_count": event_count, 

                "triage_score": triage_score, 

                "priority": priority, 

            } 

        ) 

 

results.sort( 

    key=lambda item: item["triage_score"], 

    reverse=True, 

) 

 

print("\nPrioritized Alerts") 

print("-" * 60) 

 

for result in results: 

    print( 

        f"[{result['priority']}] " 

        f"{result['alert_name']}" 

    ) 

    print(f"Severity     : {result['severity']}") 

    print(f"Confidence   : {result['confidence']}%") 

    print(f"Event Count  : {result['event_count']}") 

    print(f"Triage Score : {result['triage_score']}") 

    print() 

 

print("Summary") 

print("-" * 60) 

print(f"Total alerts : {len(results)}") 

 

priority_counts = { 

    "P1": 0, 

    "P2": 0, 

    "P3": 0, 

    "P4": 0, 

} 

 

for result in results: 

    priority_counts[result["priority"]] += 1 

 

for priority in ("P1", "P2", "P3", "P4"): 

    print(f"{priority} alerts   : {priority_counts[priority]}") 

 

report_path = Path("soc_alert_triage_report.csv").resolve() 

 

with report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "priority", 

            "alert_name", 

            "severity", 

            "confidence", 

            "event_count", 

            "triage_score", 

        ], 

    ) 

 

    writer.writeheader() 

    writer.writerows(results) 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}") 
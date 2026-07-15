#!/usr/bin/env python3 

 

import csv 

from pathlib import Path 

 

REPUTATION_DATABASE = { 

    "198.51.100.27": { 

        "reputation": "malicious", 

        "severity": "HIGH", 

    }, 

    "malicious-example.com": { 

        "reputation": "malicious", 

        "severity": "HIGH", 

    }, 

    "8.8.8.8": { 

        "reputation": "benign", 

        "severity": "INFO", 

    }, 

    "44d88612fea8a8f36de82e1278abb02f": { 

        "reputation": "malicious", 

        "severity": "CRITICAL", 

    }, 

    "2aac9cf465440e54ada96d745924b7e48f893e2b5ff8e1db0a9e2405d7f78d0a": { 

        "reputation": "suspicious", 

        "severity": "MEDIUM", 

    }, 

} 

 

SEVERITY_SCORE = { 

    "INFO": 1, 

    "LOW": 2, 

    "MEDIUM": 3, 

    "HIGH": 4, 

    "CRITICAL": 5, 

} 

 

 

def calculate_priority(severity: str, event_count: int) -> int: 

    base_score = SEVERITY_SCORE.get(severity, 1) 

    return base_score * event_count 

 

 

print("=" * 60) 

print("          CYBERLAB IOC CORRELATION ENGINE") 

print("=" * 60) 

 

input_file = input( 

    "Enter correlation file [sample_correlation_data.txt]: " 

).strip() 

 

data_path = Path( 

    input_file or "sample_correlation_data.txt" 

).expanduser().resolve() 

 

if not data_path.exists() or not data_path.is_file(): 

    print("\n[!] Correlation file does not exist.") 

    raise SystemExit(1) 

 

results = [] 

 

with data_path.open("r", encoding="utf-8", errors="ignore") as data_file: 

    for line_number, raw_line in enumerate(data_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 3: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        indicator, event_type, count_text = parts 

 

        try: 

            event_count = int(count_text) 

        except ValueError: 

            print(f"[!] Invalid count on line {line_number}: {count_text}") 

            continue 

 

        reputation_data = REPUTATION_DATABASE.get( 

            indicator, 

            { 

                "reputation": "unknown", 

                "severity": "INFO", 

            }, 

        ) 

 

        severity = reputation_data["severity"] 

        priority_score = calculate_priority(severity, event_count) 

 

        results.append( 

            { 

                "indicator": indicator, 

                "event_type": event_type, 

                "event_count": event_count, 

                "reputation": reputation_data["reputation"], 

                "severity": severity, 

                "priority_score": priority_score, 

            } 

        ) 

 

results.sort( 

    key=lambda item: item["priority_score"], 

    reverse=True, 

) 

 

print("\nCorrelated Findings") 

print("-" * 60) 

 

for result in results: 

    print(f"[{result['severity']}] {result['indicator']}") 

    print(f"Event Type     : {result['event_type']}") 

    print(f"Event Count    : {result['event_count']}") 

    print(f"Reputation     : {result['reputation']}") 

    print(f"Priority Score : {result['priority_score']}") 

    print() 

 

print("Summary") 

print("-" * 60) 

print(f"Total indicators : {len(results)}") 

 

high_priority = [ 

    result 

    for result in results 

    if result["priority_score"] >= 10 

] 

 

print(f"High priority    : {len(high_priority)}") 

 

report_path = Path("ioc_correlation_report.csv").resolve() 

 

with report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "indicator", 

            "event_type", 

            "event_count", 

            "reputation", 

            "severity", 

            "priority_score", 

        ], 

    ) 

 

    writer.writeheader() 

    writer.writerows(results) 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}") 
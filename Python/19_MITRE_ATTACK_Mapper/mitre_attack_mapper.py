#!/usr/bin/env python3 

 

import csv 

from pathlib import Path 

 

TECHNIQUE_RULES = [ 

    { 

        "keywords": ["failed ssh", "failed login", "brute force"], 

        "technique_id": "T1110", 

        "technique_name": "Brute Force", 

        "tactic": "Credential Access", 

        "severity": "HIGH", 

    }, 

    { 

        "keywords": ["powershell", "encoded command"], 

        "technique_id": "T1059.001", 

        "technique_name": "PowerShell", 

        "tactic": "Execution", 

        "severity": "HIGH", 

    }, 

    { 

        "keywords": ["network scan", "port scan"], 

        "technique_id": "T1046", 

        "technique_name": "Network Service Discovery", 

        "tactic": "Discovery", 

        "severity": "MEDIUM", 

    }, 

    { 

        "keywords": ["phishing", "suspicious attachment"], 

        "technique_id": "T1566.001", 

        "technique_name": "Spearphishing Attachment", 

        "tactic": "Initial Access", 

        "severity": "HIGH", 

    }, 

    { 

        "keywords": ["mimikatz", "credential dumping"], 

        "technique_id": "T1003", 

        "technique_name": "OS Credential Dumping", 

        "tactic": "Credential Access", 

        "severity": "CRITICAL", 

    }, 

    { 

        "keywords": ["scheduled task", "task created"], 

        "technique_id": "T1053.005", 

        "technique_name": "Scheduled Task/Job: Scheduled Task", 

        "tactic": "Persistence", 

        "severity": "HIGH", 

    }, 

    { 

        "keywords": ["suspicious domain", "dns query"], 

        "technique_id": "T1071.004", 

        "technique_name": "Application Layer Protocol: DNS", 

        "tactic": "Command and Control", 

        "severity": "MEDIUM", 

    }, 

] 

 

 

def map_event(event: str) -> list[dict[str, str]]: 

    matches = [] 

    event_lower = event.lower() 

 

    for rule in TECHNIQUE_RULES: 

        if any(keyword in event_lower for keyword in rule["keywords"]): 

            matches.append( 

                { 

                    "event": event, 

                    "technique_id": rule["technique_id"], 

                    "technique_name": rule["technique_name"], 

                    "tactic": rule["tactic"], 

                    "severity": rule["severity"], 

                } 

            ) 

 

    return matches 

 

 

print("=" * 60) 

print("        CYBERLAB MITRE ATT&CK TECHNIQUE MAPPER") 

print("=" * 60) 

 

event_file_input = input("Enter event file [sample_events.txt]: ").strip() 

event_path = Path( 

    event_file_input or "sample_events.txt" 

).expanduser().resolve() 

 

if not event_path.exists() or not event_path.is_file(): 

    print("\n[!] Event file does not exist.") 

    raise SystemExit(1) 

 

all_matches = [] 

unmapped_events = [] 

 

with event_path.open("r", encoding="utf-8", errors="ignore") as event_file: 

    for raw_line in event_file: 

        event = raw_line.strip() 

 

        if not event: 

            continue 

 

        matches = map_event(event) 

 

        if matches: 

            all_matches.extend(matches) 

        else: 

            unmapped_events.append(event) 

 

print("\nMapped Events") 

print("-" * 60) 

 

if all_matches: 

    for finding in all_matches: 

        print(f"[{finding['severity']}] {finding['technique_id']}") 

        print(f"Technique : {finding['technique_name']}") 

        print(f"Tactic    : {finding['tactic']}") 

        print(f"Event     : {finding['event']}") 

        print() 

else: 

    print("No ATT&CK techniques mapped.") 

 

print("Summary") 

print("-" * 60) 

print(f"Mapped findings : {len(all_matches)}") 

print(f"Unmapped events : {len(unmapped_events)}") 

 

report_path = Path("mitre_attack_report.csv").resolve() 

 

with report_path.open("w", newline="", encoding="utf-8") as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "severity", 

            "technique_id", 

            "technique_name", 

            "tactic", 

            "event", 

        ], 

    ) 

 

    writer.writeheader() 

    writer.writerows(all_matches) 

 

print(f"\nReport saved to: {report_path}") 
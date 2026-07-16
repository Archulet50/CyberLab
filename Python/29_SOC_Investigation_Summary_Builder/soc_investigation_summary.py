#!/usr/bin/env python3 

 

from pathlib import Path 

 

REQUIRED_FIELDS = [ 

    "case_id", 

    "title", 

    "severity", 

    "status", 

    "primary_asset", 

    "source_ip", 

    "username", 

    "mitre_technique", 

    "ioc_reputation", 

    "failed_logins", 

    "successful_logins", 

    "containment_action", 

    "analyst_recommendation", 

] 

 

print("=" * 60) 

print("      CYBERLAB SOC INVESTIGATION SUMMARY BUILDER") 

print("=" * 60) 

 

input_file = input( 

    "Enter investigation file [sample_investigation.txt]: " 

).strip() 

 

investigation_path = Path( 

    input_file or "sample_investigation.txt" 

).expanduser().resolve() 

 

if not investigation_path.exists() or not investigation_path.is_file(): 

    print("\n[!] Investigation file does not exist.") 

    raise SystemExit(1) 

 

fields = {} 

 

with investigation_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as investigation_file: 

    for raw_line in investigation_file: 

        line = raw_line.strip() 

 

        if not line or line.startswith("#") or "=" not in line: 

            continue 

 

        key, value = line.split("=", 1) 

        fields[key.strip()] = value.strip() 

 

missing_fields = [ 

    field 

    for field in REQUIRED_FIELDS 

    if not fields.get(field) 

] 

 

if missing_fields: 

    print("\n[!] Missing required fields:") 

 

    for field in missing_fields: 

        print(f"    - {field}") 

 

    raise SystemExit(1) 

 

try: 

    failed_logins = int(fields["failed_logins"]) 

    successful_logins = int(fields["successful_logins"]) 

except ValueError: 

    print("\n[!] Login counts must be numeric.") 

    raise SystemExit(1) 

 

summary_text = f""" 

CyberLab SOC Investigation Summary 

{"=" * 60} 

 

Case Information 

{"-" * 60} 

Case ID          : {fields["case_id"]} 

Title            : {fields["title"]} 

Severity         : {fields["severity"].upper()} 

Status           : {fields["status"]} 

Primary Asset    : {fields["primary_asset"]} 

 

Identity and Source 

{"-" * 60} 

Username         : {fields["username"]} 

Source IP        : {fields["source_ip"]} 

IOC Reputation   : {fields["ioc_reputation"].upper()} 

 

Authentication Activity 

{"-" * 60} 

Failed Logins    : {failed_logins} 

Successful Logins: {successful_logins} 

 

MITRE ATT&CK 

{"-" * 60} 

Technique        : {fields["mitre_technique"]} 

 

Response Actions 

{"-" * 60} 

Containment      : {fields["containment_action"]} 

Recommendation   : {fields["analyst_recommendation"]} 

 

Analyst Assessment 

{"-" * 60} 

The investigation indicates a potential credential-compromise event 

involving user {fields["username"]} and source IP {fields["source_ip"]}. 

The source indicator is classified as 

{fields["ioc_reputation"].lower()}, and the activity includes 

{failed_logins} failed login attempts followed by 

{successful_logins} successful login(s). 

 

The case is currently marked as {fields["status"]}. 

Priority should remain {fields["severity"].upper()} until identity, 

endpoint, and PowerShell activity have been fully reviewed. 

""".strip() 

 

print("\n" + summary_text) 

 

report_path = Path("soc_investigation_summary.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write(summary_text) 

    report.write("\n") 

 

print("\n" + "-" * 60) 

print(f"Summary saved to: {report_path}") 
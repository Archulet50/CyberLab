#!/usr/bin/env python3 

 

import re 

from pathlib import Path 

 

LOCAL_REPUTATION_DATABASE = { 

    "198.51.100.27": { 

        "type": "ip", 

        "reputation": "malicious", 

        "severity": "HIGH", 

        "source": "CyberLab training database", 

        "description": "Known malicious training IP", 

    }, 

    "malicious-example.com": { 

        "type": "domain", 

        "reputation": "malicious", 

        "severity": "HIGH", 

        "source": "CyberLab training database", 

        "description": "Known malicious training domain", 

    }, 

    "44d88612fea8a8f36de82e1278abb02f": { 

        "type": "md5", 

        "reputation": "malicious", 

        "severity": "CRITICAL", 

        "source": "CyberLab training database", 

        "description": "Known malicious training hash", 

    }, 

    "2aac9cf465440e54ada96d745924b7e48f893e2b5ff8e1db0a9e2405d7f78d0a": { 

        "type": "sha256", 

        "reputation": "suspicious", 

        "severity": "MEDIUM", 

        "source": "CyberLab training database", 

        "description": "Suspicious training hash", 

    }, 

    "8.8.8.8": { 

        "type": "ip", 

        "reputation": "benign", 

        "severity": "INFO", 

        "source": "CyberLab training database", 

        "description": "Known public DNS resolver", 

    }, 

} 

 

MD5_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$") 

SHA256_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$") 

IP_PATTERN = re.compile( 

    r"^(?:\d{1,3}\.){3}\d{1,3}$" 

) 

DOMAIN_PATTERN = re.compile( 

    r"^(?=.{1,253}$)" 

    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+" 

    r"[A-Za-z]{2,63}$" 

) 

 

 

def classify_indicator(value: str) -> str: 

    if SHA256_PATTERN.fullmatch(value): 

        return "sha256" 

 

    if MD5_PATTERN.fullmatch(value): 

        return "md5" 

 

    if IP_PATTERN.fullmatch(value): 

        return "ip" 

 

    if DOMAIN_PATTERN.fullmatch(value): 

        return "domain" 

 

    return "unknown" 

 

 

print("=" * 60) 

print("           CYBERLAB IOC REPUTATION CHECKER") 

print("=" * 60) 

 

input_file = input("Enter IOC file [sample_iocs.txt]: ").strip() 

 

ioc_path = Path( 

    input_file or "sample_iocs.txt" 

).expanduser().resolve() 

 

if not ioc_path.exists() or not ioc_path.is_file(): 

    print("\n[!] IOC file does not exist.") 

    raise SystemExit(1) 

 

results = [] 

 

with ioc_path.open("r", encoding="utf-8", errors="ignore") as ioc_file: 

    for raw_line in ioc_file: 

        indicator = raw_line.strip() 

 

        if not indicator or indicator.startswith("#"): 

            continue 

 

        indicator_type = classify_indicator(indicator) 

        reputation_data = LOCAL_REPUTATION_DATABASE.get(indicator) 

 

        if reputation_data: 

            result = { 

                "indicator": indicator, 

                "type": reputation_data["type"], 

                "reputation": reputation_data["reputation"], 

                "severity": reputation_data["severity"], 

                "source": reputation_data["source"], 

                "description": reputation_data["description"], 

            } 

        else: 

            result = { 

                "indicator": indicator, 

                "type": indicator_type, 

                "reputation": "unknown", 

                "severity": "INFO", 

                "source": "No match", 

                "description": "Indicator not found in local database", 

            } 

 

        results.append(result) 

 

print("\nReputation Results") 

print("-" * 60) 

 

for result in results: 

    print(f"[{result['severity']}] {result['indicator']}") 

    print(f"Type        : {result['type']}") 

    print(f"Reputation  : {result['reputation']}") 

    print(f"Source      : {result['source']}") 

    print(f"Description : {result['description']}") 

    print() 

 

summary = { 

    "malicious": 0, 

    "suspicious": 0, 

    "benign": 0, 

    "unknown": 0, 

} 

 

for result in results: 

    summary[result["reputation"]] += 1 

 

print("Summary") 

print("-" * 60) 

print(f"Malicious  : {summary['malicious']}") 

print(f"Suspicious : {summary['suspicious']}") 

print(f"Benign     : {summary['benign']}") 

print(f"Unknown    : {summary['unknown']}") 

 

report_path = Path("ioc_reputation_report.txt").resolve() 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab IOC Reputation Report\n") 

    report.write("=" * 60 + "\n\n") 

 

    for result in results: 

        report.write(f"Indicator: {result['indicator']}\n") 

        report.write(f"Type: {result['type']}\n") 

        report.write(f"Reputation: {result['reputation']}\n") 

        report.write(f"Severity: {result['severity']}\n") 

        report.write(f"Source: {result['source']}\n") 

        report.write(f"Description: {result['description']}\n\n") 

 

    report.write("Summary\n") 

    report.write("-" * 60 + "\n") 

    report.write(f"Malicious: {summary['malicious']}\n") 

    report.write(f"Suspicious: {summary['suspicious']}\n") 

    report.write(f"Benign: {summary['benign']}\n") 

    report.write(f"Unknown: {summary['unknown']}\n") 

 

print("\n" + "-" * 60) 

print(f"Report saved to: {report_path}") 
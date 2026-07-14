#!/usr/bin/env python3 

 

import hashlib 

from pathlib import Path 

 

SUSPICIOUS_FILENAMES = { 

    "mimikatz.exe", 

    "psexec.exe", 

    "nc.exe", 

    "netcat.exe", 

    "ransomware.exe", 

    "malware.exe", 

} 

 

# Training hashes only. Add authorized indicators here later. 

KNOWN_BAD_HASHES = { 

    # "sha256_hash_here": "Description" 

} 

 

 

def calculate_sha256(file_path: Path) -> str: 

    sha256 = hashlib.sha256() 

 

    with file_path.open("rb") as file: 

        while True: 

            chunk = file.read(4096) 

 

            if not chunk: 

                break 

 

            sha256.update(chunk) 

 

    return sha256.hexdigest() 

 

 

def scan_folder(folder: Path) -> list[dict[str, str]]: 

    findings = [] 

 

    for file_path in folder.rglob("*"): 

        if not file_path.is_file(): 

            continue 

 

        reasons = [] 

 

        if file_path.name.lower() in SUSPICIOUS_FILENAMES: 

            reasons.append("Suspicious filename") 

 

        try: 

            file_hash = calculate_sha256(file_path) 

        except (PermissionError, OSError) as error: 

            print(f"[!] Could not read {file_path}: {error}") 

            continue 

 

        if file_hash in KNOWN_BAD_HASHES: 

            reasons.append( 

                f"Known bad hash: {KNOWN_BAD_HASHES[file_hash]}" 

            ) 

 

        if reasons: 

            findings.append( 

                { 

                    "file": str(file_path), 

                    "sha256": file_hash, 

                    "reasons": ", ".join(reasons), 

                } 

            ) 

 

    return findings 

 

 

print("=" * 60) 

print("               CYBERLAB IOC SCANNER") 

print("=" * 60) 

 

folder_input = input("Enter folder to scan: ").strip() 

folder = Path(folder_input).expanduser().resolve() 

 

if not folder.exists() or not folder.is_dir(): 

    print("\n[!] Folder does not exist or is not a directory.") 

    raise SystemExit(1) 

 

print(f"\nScanning: {folder}\n") 

 

results = scan_folder(folder) 

 

print("Scan Results") 

print("-" * 60) 

 

if results: 

    for finding in results: 

        print(f"[!] File    : {finding['file']}") 

        print(f"    Reason  : {finding['reasons']}") 

        print(f"    SHA-256 : {finding['sha256']}") 

        print() 

else: 

    print("[+] No configured indicators were detected.") 

 

report_path = Path("ioc_scan_report.txt") 

 

with report_path.open("w", encoding="utf-8") as report: 

    report.write("CyberLab IOC Scan Report\n") 

    report.write("=" * 60 + "\n") 

    report.write(f"Scanned folder: {folder}\n") 

    report.write(f"Findings: {len(results)}\n\n") 

 

    for finding in results: 

        report.write(f"File: {finding['file']}\n") 

        report.write(f"Reason: {finding['reasons']}\n") 

        report.write(f"SHA-256: {finding['sha256']}\n\n") 

 

print("-" * 60) 

print(f"Findings: {len(results)}") 

print(f"Report saved to: {report_path.resolve()}") 
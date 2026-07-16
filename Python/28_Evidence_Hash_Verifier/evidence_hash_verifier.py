#!/usr/bin/env python3 

 

import hashlib 

import json 

from pathlib import Path 

 

BASELINE_FILE = Path("evidence_hashes.json") 

 

 

def calculate_sha256(file_path: Path) -> str: 

    sha256 = hashlib.sha256() 

 

    with file_path.open("rb") as evidence_file: 

        while True: 

            chunk = evidence_file.read(4096) 

 

            if not chunk: 

                break 

 

            sha256.update(chunk) 

 

    return sha256.hexdigest() 

 

 

def scan_evidence_folder(folder: Path) -> dict[str, str]: 

    hashes = {} 

 

    for file_path in sorted(folder.rglob("*")): 

        if not file_path.is_file(): 

            continue 

 

        relative_path = str(file_path.relative_to(folder)) 

 

        try: 

            hashes[relative_path] = calculate_sha256(file_path) 

        except (PermissionError, OSError) as error: 

            print(f"[!] Could not read {file_path}: {error}") 

 

    return hashes 

 

 

print("=" * 60) 

print("          CYBERLAB EVIDENCE HASH VERIFIER") 

print("=" * 60) 

 

folder_input = input("Enter evidence folder [evidence]: ").strip() 

 

evidence_folder = Path( 

    folder_input or "evidence" 

).expanduser().resolve() 

 

if not evidence_folder.exists() or not evidence_folder.is_dir(): 

    print("\n[!] Evidence folder does not exist.") 

    raise SystemExit(1) 

 

current_hashes = scan_evidence_folder(evidence_folder) 

 

if not current_hashes: 

    print("\n[!] No evidence files were found.") 

    raise SystemExit(1) 

 

if not BASELINE_FILE.exists(): 

    with BASELINE_FILE.open("w", encoding="utf-8") as baseline: 

        json.dump(current_hashes, baseline, indent=4) 

 

    print("\nBaseline Created") 

    print("-" * 60) 

 

    for file_name, file_hash in current_hashes.items(): 

        print(f"File   : {file_name}") 

        print(f"SHA-256: {file_hash}") 

        print() 

 

    print(f"Files recorded : {len(current_hashes)}") 

    print(f"Baseline saved : {BASELINE_FILE.resolve()}") 

 

else: 

    with BASELINE_FILE.open("r", encoding="utf-8") as baseline: 

        saved_hashes = json.load(baseline) 

 

    added = sorted(set(current_hashes) - set(saved_hashes)) 

    missing = sorted(set(saved_hashes) - set(current_hashes)) 

 

    modified = sorted( 

        file_name 

        for file_name in current_hashes 

        if ( 

            file_name in saved_hashes 

            and current_hashes[file_name] != saved_hashes[file_name] 

        ) 

    ) 

 

    verified = sorted( 

        file_name 

        for file_name in current_hashes 

        if ( 

            file_name in saved_hashes 

            and current_hashes[file_name] == saved_hashes[file_name] 

        ) 

    ) 

 

    print("\nVerification Results") 

    print("-" * 60) 

 

    for file_name in verified: 

        print(f"[VERIFIED] {file_name}") 

 

    for file_name in modified: 

        print(f"[MODIFIED] {file_name}") 

 

    for file_name in added: 

        print(f"[ADDED]    {file_name}") 

 

    for file_name in missing: 

        print(f"[MISSING]  {file_name}") 

 

    print("\nSummary") 

    print("-" * 60) 

    print(f"Verified : {len(verified)}") 

    print(f"Modified : {len(modified)}") 

    print(f"Added    : {len(added)}") 

    print(f"Missing  : {len(missing)}") 

 

    report_path = Path("evidence_verification_report.txt").resolve() 

 

    with report_path.open("w", encoding="utf-8") as report: 

        report.write("CyberLab Evidence Verification Report\n") 

        report.write("=" * 60 + "\n") 

        report.write(f"Evidence folder: {evidence_folder}\n\n") 

 

        for file_name in verified: 

            report.write(f"[VERIFIED] {file_name}\n") 

 

        for file_name in modified: 

            report.write(f"[MODIFIED] {file_name}\n") 

 

        for file_name in added: 

            report.write(f"[ADDED] {file_name}\n") 

 

        for file_name in missing: 

            report.write(f"[MISSING] {file_name}\n") 

 

        report.write("\nSummary\n") 

        report.write("-" * 60 + "\n") 

        report.write(f"Verified: {len(verified)}\n") 

        report.write(f"Modified: {len(modified)}\n") 

        report.write(f"Added: {len(added)}\n") 

        report.write(f"Missing: {len(missing)}\n") 

 

    print(f"\nReport saved to: {report_path}") 
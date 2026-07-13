#!/usr/bin/env python3 

 

import hashlib 

import json 

import os 

from pathlib import Path 

 

BASELINE_FILE = "baseline.json" 

 

 

def calculate_hash(file_path: Path) -> str: 

    sha256 = hashlib.sha256() 

 

    with file_path.open("rb") as file: 

        while chunk := file.read(4096): 

            sha256.update(chunk) 

 

    return sha256.hexdigest() 

 

 

def scan_directory(folder: Path) -> dict[str, str]: 

    results = {} 

 

    for path in folder.rglob("*"): 

        if path.is_file() and path.name != BASELINE_FILE: 

            try: 

                relative_path = str(path.relative_to(folder)) 

                results[relative_path] = calculate_hash(path) 

            except (PermissionError, OSError) as error: 

                print(f"[!] Could not read {path}: {error}") 

 

    return results 

 

 

def save_baseline(data: dict[str, str]) -> None: 

    with open(BASELINE_FILE, "w", encoding="utf-8") as file: 

        json.dump(data, file, indent=4) 

 

 

def load_baseline() -> dict[str, str]: 

    with open(BASELINE_FILE, "r", encoding="utf-8") as file: 

        return json.load(file) 

 

 

print("=" * 60) 

print("          CYBERLAB FILE INTEGRITY MONITOR") 

print("=" * 60) 

 

folder_input = input("Enter folder to monitor: ").strip() 

folder = Path(folder_input).expanduser().resolve() 

 

if not folder.exists() or not folder.is_dir(): 

    print("\n[!] Folder does not exist or is not a directory.") 

    raise SystemExit(1) 

 

current_state = scan_directory(folder) 

 

if not os.path.exists(BASELINE_FILE): 

    save_baseline(current_state) 

    print("\n[+] Baseline created successfully.") 

    print(f"[+] Files recorded: {len(current_state)}") 

    print(f"[+] Baseline file: {Path(BASELINE_FILE).resolve()}") 

 

else: 

    baseline = load_baseline() 

 

    added = sorted(set(current_state) - set(baseline)) 

    deleted = sorted(set(baseline) - set(current_state)) 

    modified = sorted( 

        path 

        for path in current_state 

        if path in baseline and current_state[path] != baseline[path] 

    ) 

 

    print("\nIntegrity Check Results") 

    print("-" * 60) 

 

    if not added and not deleted and not modified: 

        print("[+] No changes detected.") 

 

    for path in added: 

        print(f"[+] ADDED    : {path}") 

 

    for path in deleted: 

        print(f"[-] DELETED  : {path}") 

 

    for path in modified: 

        print(f"[!] MODIFIED : {path}") 

 

    print("\nSummary") 

    print("-" * 60) 

    print(f"Added files    : {len(added)}") 

    print(f"Deleted files  : {len(deleted)}") 

    print(f"Modified files : {len(modified)}") 

 

    update = input("\nUpdate baseline? (y/n): ").strip().lower() 

 

    if update == "y": 

        save_baseline(current_state) 

        print("[+] Baseline updated.") 

    else: 

        print("[*] Baseline unchanged.") 


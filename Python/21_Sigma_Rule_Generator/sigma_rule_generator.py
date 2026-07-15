#!/usr/bin/env python3 

 

from pathlib import Path 

 

print("=" * 60) 

print("          CYBERLAB SIGMA RULE GENERATOR") 

print("=" * 60) 

 

input_file = input( 

    "Enter detection file [sample_detection.txt]: " 

).strip() 

 

detection_path = Path( 

    input_file or "sample_detection.txt" 

).expanduser().resolve() 

 

if not detection_path.exists() or not detection_path.is_file(): 

    print("\n[!] Detection file does not exist.") 

    raise SystemExit(1) 

 

fields = {} 

 

with detection_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as detection_file: 

    for raw_line in detection_file: 

        line = raw_line.strip() 

 

        if not line or line.startswith("#") or "=" not in line: 

            continue 

 

        key, value = line.split("=", 1) 

        fields[key.strip()] = value.strip() 

 

required_fields = [ 

    "title", 

    "description", 

    "author", 

    "logsource_category", 

    "product", 

    "image", 

    "commandline_contains", 

    "level", 

    "mitre_attack", 

] 

 

missing_fields = [ 

    field for field in required_fields if not fields.get(field) 

] 

 

if missing_fields: 

    print("\n[!] Missing required fields:") 

    for field in missing_fields: 

        print(f"    - {field}") 

    raise SystemExit(1) 

 

rule_name = ( 

    fields["title"] 

    .lower() 

    .replace(" ", "_") 

    .replace("-", "_") 

) 

 

sigma_rule = f"""title: {fields['title']} 

id: cyberlab-{rule_name} 

status: experimental 

description: {fields['description']} 

author: {fields['author']} 

date: 2026/07/14 

references: 

    - https://attack.mitre.org/techniques/{fields['mitre_attack'].replace('.', '/')}/ 

logsource: 

    category: {fields['logsource_category']} 

    product: {fields['product']} 

detection: 

    selection: 

        Image|endswith: '\\\\{fields['image']}' 

        CommandLine|contains: '{fields['commandline_contains']}' 

    condition: selection 

falsepositives: 

    - Administrative or troubleshooting activity 

level: {fields['level']} 

tags: 

    - attack.{fields['mitre_attack'].lower()} 

""" 

 

output_path = Path("generated_sigma_rule.yml").resolve() 

 

with output_path.open("w", encoding="utf-8") as output_file: 

    output_file.write(sigma_rule) 

 

print("\nGenerated Sigma Rule") 

print("-" * 60) 

print(sigma_rule) 

 

print("-" * 60) 

print(f"Rule saved to: {output_path}") 
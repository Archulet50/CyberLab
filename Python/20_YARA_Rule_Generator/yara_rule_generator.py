#!/usr/bin/env python3 

 

from pathlib import Path 

 

print("=" * 60) 

print("        CYBERLAB YARA RULE GENERATOR") 

print("=" * 60) 

 

filename = input("Input string file [sample_strings.txt]: ").strip() 

 

if filename == "": 

    filename = "sample_strings.txt" 

 

path = Path(filename) 

 

if not path.exists(): 

    print("\nFile not found.") 

    quit() 

 

with open(path, "r") as f: 

    strings = [line.strip() for line in f if line.strip()] 

 

rule_name = input("\nRule name: ").strip() 

 

if rule_name == "": 

    rule_name = "CyberLab_Rule" 

 

output = []#!/usr/bin/env python3 

 

from pathlib import Path 

 

print("=" * 60) 

print("        CYBERLAB YARA RULE GENERATOR") 

print("=" * 60) 

 

filename = input("Input string file [sample_strings.txt]: ").strip() 

 

if filename == "": 

    filename = "sample_strings.txt" 

 

path = Path(filename) 

 

if not path.exists(): 

    print("\nFile not found.") 

    quit() 

 

with open(path, "r") as f: 

    strings = [line.strip() for line in f if line.strip()] 

 

rule_name = input("\nRule name: ").strip() 

 

if rule_name == "": 

    rule_name = "CyberLab_Rule" 

 

output = [] 

 

output.append(f"rule {rule_name}") 

output.append("{") 

output.append("    strings:") 

 

for i, s in enumerate(strings): 

    output.append(f'        $s{i+1} = "{s}" ascii') 

 

output.append("") 

output.append("    condition:") 

output.append("        any of them") 

output.append("}") 

 

rule_text = "\n".join(output) 

 

print("\nGenerated Rule\n") 

print(rule_text) 

 

outfile = "generated_rule.yar" 

 

with open(outfile, "w") as f: 

    f.write(rule_text) 

 

print("\n--------------------------------------------") 

print(f"Rule saved as {outfile}") 

 

output.append(f"rule {rule_name}") 

output.append("{") 

output.append("    strings:") 

 

for i, s in enumerate(strings): 

    output.append(f'        $s{i+1} = "{s}" ascii') 

 

output.append("") 

output.append("    condition:") 

output.append("        any of them") 

output.append("}") 

 

rule_text = "\n".join(output) 

 

print("\nGenerated Rule\n") 

print(rule_text) 

 

outfile = "generated_rule.yar" 

 

with open(outfile, "w") as f: 

    f.write(rule_text) 

 

print("\n--------------------------------------------") 

print(f"Rule saved as {outfile}") 
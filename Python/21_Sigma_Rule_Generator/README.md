# Sigma Rule Generator

## Purpose

Generates a basic Sigma detection rule from a structured text file.

## Features

- Reads detection metadata from a text file
- Generates Sigma-compatible YAML
- Adds MITRE ATT&CK tags
- Supports configurable severity
- Creates a reusable `.yml` detection rule

## Usage

```bash
python3 sigma_rule_generator.py
```

Press Enter to use the included `sample_detection.txt`.

## Skills Demonstrated

- Python
- Detection Engineering
- Sigma Rules
- YAML Generation
- MITRE ATT&CK Mapping
- SIEM-agnostic Detection Logic

## Ethical Use

Use generated rules only for authorized defensive-security monitoring and testing.
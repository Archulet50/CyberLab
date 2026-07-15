# Incident Report Generator

## Purpose

Converts structured security findings into prioritized incident reports for SOC and incident-response workflows.

## Features

- Reads incident date, alert name, severity, and affected asset
- Sorts incidents by severity
- Produces an executive summary
- Generates detailed text and CSV reports
- Validates malformed input records

## Usage

```bash
python incident_report_generator.py
```

Press Enter to use the included `sample_incidents.txt`.

## Skills Demonstrated

- Python
- Incident Response
- SOC Reporting
- Severity Prioritization
- Data Parsing
- Text and CSV Report Generation

## Limitation

This training tool uses simplified incident records. Production reports should also include timelines, evidence, containment actions, affected users, business impact, and remediation status.
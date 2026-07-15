# SOC Alert Triage

## Purpose

Prioritizes security alerts using severity, analyst confidence, and event volume.

## Features

- Reads structured alert data
- Calculates a triage score
- Assigns P1–P4 priorities
- Sorts alerts by urgency
- Validates numeric input
- Exports a CSV report

## Usage

```bash
python soc_alert_triage.py
```

Press Enter to use the included `sample_alerts.txt`.

## Skills Demonstrated

- Python
- SOC Alert Triage
- Security Operations
- Risk Scoring
- Incident Prioritization
- CSV Reporting

## Limitation

This is a training model. Production triage should also consider asset criticality, user context, threat intelligence, and business impact.
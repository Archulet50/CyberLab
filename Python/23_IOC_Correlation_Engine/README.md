# IOC Correlation Engine

## Purpose

Correlates security-event activity with IOC reputation data and assigns a priority score to each finding.

## Features

- Reads indicator, event type, and event count data
- Matches indicators against a local reputation database
- Applies severity scoring
- Calculates priority scores
- Sorts findings by priority
- Exports a CSV report

## Usage

```bash
python ioc_correlation_engine.py
```

Press Enter to use the included `sample_correlation_data.txt`.

## Skills Demonstrated

- Python
- IOC Correlation
- Threat Intelligence
- SOC Alert Prioritization
- Risk Scoring
- CSV Reporting

## Limitation

Priority score should be reviewed alongside reputation, severity, and event context. High event volume does not automatically indicate malicious activity.
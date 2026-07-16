# Mini SIEM Dashboard 

 

## Purpose 

 

Provides a terminal-based SIEM dashboard that summarizes alerts, prioritizes events, tracks case status, and displays MITRE ATT&CK activity. 

 

## Features 

 

- Parses timestamped SIEM event data 

- Counts alerts by severity 

- Tracks open, investigating, contained, and closed cases 

- Calculates alert priority scores 

- Sorts alerts by urgency 

- Summarizes MITRE ATT&CK activity 

- Generates text and CSV reports 

 

## Usage 

 

```bash 

python mini_siem_dashboard.py 

``` 

 

Press Enter to use the included `sample_siem_events.txt`. 

 

## Skills Demonstrated 

 

- Python 

- SIEM Operations 

- SOC Monitoring 

- Alert Prioritization 

- MITRE ATT&CK 

- Incident Status Tracking 

- Text and CSV Reporting 

 

## Limitation 

 

This is a terminal-based training dashboard using static sample data. A production SIEM would ingest live events, support continuous searching, dashboards, correlation rules, user access controls, case management, and alert notifications. 
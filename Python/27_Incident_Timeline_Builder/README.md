# Incident Timeline Builder

## Purpose

Builds a chronological timeline of security events and calculates elapsed time from the first observed event.

## Features

- Parses timestamped incident events
- Sorts events chronologically
- Calculates elapsed time between events
- Measures total incident duration
- Generates text and CSV timeline reports
- Skips malformed records safely

## Usage

```bash
python incident_timeline_builder.py
```

Press Enter to use the included `sample_timeline.txt`.

## Skills Demonstrated

- Python
- Incident Response
- Timeline Analysis
- Date and Time Parsing
- SOC Investigation
- Text and CSV Reporting

## Limitation

This is a simplified training tool. Production timelines should also include evidence sources, analyst notes, time zones, case IDs, and chain-of-custody details.
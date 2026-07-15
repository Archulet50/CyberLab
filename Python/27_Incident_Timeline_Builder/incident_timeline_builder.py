#!/usr/bin/env python3 

 

import csv 

from datetime import datetime 

from pathlib import Path 

 

TIME_FORMAT = "%Y-%m-%d %H:%M:%S" 

 

SEVERITY_RANK = { 

    "LOW": 1, 

    "MEDIUM": 2, 

    "HIGH": 3, 

    "CRITICAL": 4, 

} 

 

print("=" * 60) 

print("        CYBERLAB INCIDENT TIMELINE BUILDER") 

print("=" * 60) 

 

input_file = input( 

    "Enter timeline file [sample_timeline.txt]: " 

).strip() 

 

timeline_path = Path( 

    input_file or "sample_timeline.txt" 

).expanduser().resolve() 

 

if not timeline_path.exists() or not timeline_path.is_file(): 

    print("\n[!] Timeline file does not exist.") 

    raise SystemExit(1) 

 

events = [] 

 

with timeline_path.open( 

    "r", 

    encoding="utf-8", 

    errors="ignore", 

) as timeline_file: 

    for line_number, raw_line in enumerate(timeline_file, start=1): 

        line = raw_line.strip() 

 

        if not line or line.startswith("#"): 

            continue 

 

        parts = [part.strip() for part in line.split(",")] 

 

        if len(parts) != 4: 

            print(f"[!] Skipping malformed line {line_number}: {line}") 

            continue 

 

        timestamp_text, description, source, severity = parts 

 

        try: 

            timestamp = datetime.strptime(timestamp_text, TIME_FORMAT) 

        except ValueError: 

            print( 

                f"[!] Invalid timestamp on line " 

                f"{line_number}: {timestamp_text}" 

            ) 

            continue 

 

        severity = severity.upper() 

 

        events.append( 

            { 

                "timestamp": timestamp, 

                "description": description, 

                "source": source, 

                "severity": severity, 

                "severity_rank": SEVERITY_RANK.get(severity, 0), 

            } 

        ) 

 

events.sort(key=lambda item: item["timestamp"]) 

 

if not events: 

    print("\n[!] No valid timeline events were found.") 

    raise SystemExit(1) 

 

first_event_time = events[0]["timestamp"] 

 

print("\nIncident Timeline") 

print("-" * 60) 

 

for event in events: 

    elapsed = event["timestamp"] - first_event_time 

    elapsed_seconds = int(elapsed.total_seconds()) 

 

    hours, remainder = divmod(elapsed_seconds, 3600) 

    minutes, seconds = divmod(remainder, 60) 

 

    elapsed_text = f"{hours:02}:{minutes:02}:{seconds:02}" 

 

    print( 

        f"[{event['severity']}] " 

        f"{event['timestamp'].strftime(TIME_FORMAT)}" 

    ) 

    print(f"Elapsed     : {elapsed_text}") 

    print(f"Source      : {event['source']}") 

    print(f"Description : {event['description']}") 

    print() 

 

incident_duration = events[-1]["timestamp"] - first_event_time 

duration_seconds = int(incident_duration.total_seconds()) 

 

duration_hours, remainder = divmod(duration_seconds, 3600) 

duration_minutes, duration_seconds = divmod(remainder, 60) 

 

print("Summary") 

print("-" * 60) 

print(f"Total events      : {len(events)}") 

print(f"First event       : {events[0]['timestamp'].strftime(TIME_FORMAT)}") 

print(f"Last event        : {events[-1]['timestamp'].strftime(TIME_FORMAT)}") 

print( 

    f"Incident duration : " 

    f"{duration_hours:02}:{duration_minutes:02}:{duration_seconds:02}" 

) 

 

text_report_path = Path("incident_timeline_report.txt").resolve() 

csv_report_path = Path("incident_timeline_report.csv").resolve() 

 

with text_report_path.open( 

    "w", 

    encoding="utf-8", 

) as report: 

    report.write("CyberLab Incident Timeline Report\n") 

    report.write("=" * 60 + "\n\n") 

 

    for event in events: 

        elapsed = event["timestamp"] - first_event_time 

        elapsed_seconds = int(elapsed.total_seconds()) 

 

        hours, remainder = divmod(elapsed_seconds, 3600) 

        minutes, seconds = divmod(remainder, 60) 

 

        report.write( 

            f"[{event['severity']}] " 

            f"{event['timestamp'].strftime(TIME_FORMAT)}\n" 

        ) 

        report.write( 

            f"Elapsed: {hours:02}:{minutes:02}:{seconds:02}\n" 

        ) 

        report.write(f"Source: {event['source']}\n") 

        report.write(f"Description: {event['description']}\n\n") 

 

with csv_report_path.open( 

    "w", 

    newline="", 

    encoding="utf-8", 

) as report: 

    writer = csv.DictWriter( 

        report, 

        fieldnames=[ 

            "timestamp", 

            "elapsed", 

            "source", 

            "severity", 

            "description", 

        ], 

    ) 

 

    writer.writeheader() 

 

    for event in events: 

        elapsed = event["timestamp"] - first_event_time 

        elapsed_seconds = int(elapsed.total_seconds()) 

 

        hours, remainder = divmod(elapsed_seconds, 3600) 

        minutes, seconds = divmod(remainder, 60) 

 

        writer.writerow( 

            { 

                "timestamp": event["timestamp"].strftime(TIME_FORMAT), 

                "elapsed": f"{hours:02}:{minutes:02}:{seconds:02}", 

                "source": event["source"], 

                "severity": event["severity"], 

                "description": event["description"], 

            } 

        ) 

 

print("\n" + "-" * 60) 

print(f"Text report saved to: {text_report_path}") 

print(f"CSV report saved to : {csv_report_path}") 
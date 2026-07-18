#!/usr/bin/env python3
"""
CyberLab Mission 17: PCAP Analyzer

Reads a PCAP file and summarizes:
- Total packets
- Protocol counts
- Top source IP addresses
- Top destination IP addresses
- Top destination ports
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, rdpcap
from scapy.error import Scapy_Exception


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and display network traffic statistics."
    )
    parser.add_argument(
        "pcap_file",
        type=Path,
        help="Path to the PCAP file to analyze",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top results to display (default: 10)",
    )
    return parser.parse_args()


def analyze_pcap(pcap_path: Path) -> dict[str, object]:
    """Read and analyze packets from a PCAP file."""
    packets = rdpcap(str(pcap_path))

    protocol_counts: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    destination_ports: Counter[int] = Counter()

    for packet in packets:
        if packet.haslayer(ARP):
            protocol_counts["ARP"] += 1
            continue

        if not packet.haslayer(IP):
            protocol_counts["Other"] += 1
            continue

        ip_layer = packet[IP]
        source_ips[ip_layer.src] += 1
        destination_ips[ip_layer.dst] += 1

        if packet.haslayer(TCP):
            protocol_counts["TCP"] += 1
            destination_ports[int(packet[TCP].dport)] += 1
        elif packet.haslayer(UDP):
            protocol_counts["UDP"] += 1
            destination_ports[int(packet[UDP].dport)] += 1
        elif packet.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts["Other IP"] += 1

    return {
        "total_packets": len(packets),
        "protocol_counts": protocol_counts,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "destination_ports": destination_ports,
    }


def print_counter(title: str, counter: Counter, limit: int) -> None:
    """Print the most common values from a Counter."""
    print(f"\n{title}")
    print("-" * len(title))

    if not counter:
        print("No data found.")
        return

    for value, count in counter.most_common(limit):
        print(f"{str(value):<25} {count:>6}")


def print_report(results: dict[str, object], limit: int) -> None:
    """Display the analysis report."""
    print("\n" + "=" * 60)
    print("CYBERLAB PCAP ANALYZER")
    print("=" * 60)
    print(f"Total packets: {results['total_packets']}")

    print_counter(
        "Protocol Counts",
        results["protocol_counts"],
        limit,
    )
    print_counter(
        "Top Source IP Addresses",
        results["source_ips"],
        limit,
    )
    print_counter(
        "Top Destination IP Addresses",
        results["destination_ips"],
        limit,
    )
    print_counter(
        "Top Destination Ports",
        results["destination_ports"],
        limit,
    )

    print("\nAnalysis complete.")


def main() -> int:
    """Run the PCAP analyzer."""
    args = parse_arguments()
    pcap_path: Path = args.pcap_file

    if args.top < 1:
        print("Error: --top must be greater than zero.", file=sys.stderr)
        return 1

    if not pcap_path.exists():
        print(f"Error: File not found: {pcap_path}", file=sys.stderr)
        return 1

    if not pcap_path.is_file():
        print(f"Error: Not a file: {pcap_path}", file=sys.stderr)
        return 1

    try:
        results = analyze_pcap(pcap_path)
    except PermissionError:
        print(f"Error: Permission denied: {pcap_path}", file=sys.stderr)
        return 1
    except Scapy_Exception as error:
        print(f"Error reading PCAP file: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"File error: {error}", file=sys.stderr)
        return 1

    print_report(results, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
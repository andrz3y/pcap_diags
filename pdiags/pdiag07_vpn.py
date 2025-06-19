"""
PCAP ANALYZER

NAME:       pdiag07_vpn.py

VERSION:    1.1.6

-----------------
- Detect VPN traffic (OpenVPN, L2TP, PPTP, IPsec, WireGuard, GRE)
- Summary of total vs VPN packets
- Protocol breakdown and percentages
- Endpoint counts
-----------------
"""

__version__ = "1.1.6"

#UPDATE:1.1.4_remove_pyshark
import subprocess
import datetime                           # for timestamp parsing if needed
from pathlib import Path
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich import box
import argparse
import sys

console = Console()

# The Wireshark display filter we use
VPN_FILTER = "(udp.port==1194 or tcp.port==1194) or udp.port==1701 or tcp.port==1723 or ip.proto==47 or udp.port==500 or udp.port==4500 or udp.port==51820"

def analyze(pcap_file):
    #UPDATE:1.1.4_divider_start
    console.rule("[bold yellow]— VPN Analysis START —[/bold yellow]")

    # 1) Count total packets
    total_packets = 0
    cmd_total = ["tshark", "-r", str(pcap_file), "-T", "fields", "-E", "separator=,", "-e", "frame.number"]
    proc = subprocess.Popen(cmd_total, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in proc.stdout:
        total_packets += 1
    proc.stdout.close()
    proc.wait()

    # 2) Extract VPN packets
    vpn_packets = 0
    proto_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)

    cmd_vpn = [
        "tshark", "-r", str(pcap_file),
        "-Y", VPN_FILTER,
        "-T", "fields", "-E", "separator=,",
        "-e", "frame.number",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport"
    ]
    proc2 = subprocess.Popen(cmd_vpn, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in proc2.stdout:
        parts = line.strip().split(",")
        if len(parts) < 8:
            continue
        vpn_packets += 1
        src, dst, proto = parts[1], parts[2], parts[3]
        proto_counts[proto] += 1
        endpoint_counts[(src, dst, proto)] += 1
    proc2.stdout.close()
    proc2.wait()

    # 3) Summary table
    console.print("\n[bold blue][*] VPN Traffic Summary:[/bold blue]\n")
    sum_tbl = Table(show_lines=False, box=box.MINIMAL)
    sum_tbl.add_column("Metric")
    sum_tbl.add_column("Value", justify="right")
    sum_tbl.add_row("Total packets", str(total_packets))
    sum_tbl.add_row("VPN packets", str(vpn_packets))
    pct = (vpn_packets / total_packets * 100) if total_packets else 0
    sum_tbl.add_row("% VPN", f"{pct:.1f}%")
    console.print(sum_tbl)

    # 4) Protocol breakdown
    console.print("\n[bold blue][*] VPN Protocol Breakdown:[/bold blue]\n")
    proto_tbl = Table(show_lines=True, box=box.SIMPLE)
    proto_tbl.add_column("Protocol", style="green")
    proto_tbl.add_column("Count", justify="right")
    proto_tbl.add_column("%", justify="right")
    for proto, cnt in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
        pctp = (cnt / vpn_packets * 100) if vpn_packets else 0
        proto_tbl.add_row(proto, str(cnt), f"{pctp:.1f}%")
    console.print(proto_tbl)

    # 5) Endpoints table
    console.print("\n[bold blue][*] VPN Endpoints:[/bold blue]\n")
    ep_tbl = Table(show_lines=True, box=box.MINIMAL)
    ep_tbl.add_column("Source", style="cyan")
    ep_tbl.add_column("Destination", style="magenta")
    ep_tbl.add_column("Protocol", style="green")
    ep_tbl.add_column("Count", justify="right")
    for (src, dst, proto), cnt in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True):
        ep_tbl.add_row(src, dst, proto, str(cnt))
    console.print(ep_tbl)

    #UPDATE:1.1.4_divider_end
    console.rule("[bold yellow]— VPN Analysis END —[/bold yellow]")

def main():
    parser = argparse.ArgumentParser(description="Analyze VPN-related traffic in a PCAP.")
    parser.add_argument('-f', '--file', required=True, help="Path to PCAP file")
    args = parser.parse_args()
    analyze(Path(args.file))

if __name__ == "__main__":
    main()

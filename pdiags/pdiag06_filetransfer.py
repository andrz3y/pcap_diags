"""
PCAP ANALYZER

NAME:       pdiag06_filetransfer.py 

VERSION:    1.1.4

-----------------
- Detect file-transfer protocols (FTP, SSH/SCP, SMB, NFS, HTTP/S, TFTP)
- Count per-protocol packets and % of total PCAP
- Identify continuation frames
- Identify NFS performance signatures (Sig1–Sig4)

#UPDATE:1.1.4_filters_header - Wireshark filters for signatures
#   Sig4 Delayed ACKs:    (tcp.dstport==2049)&&(tcp.flags.ack==1)&&(frame.time_delta>=0.1)
#   Sig3 Slow Start:      (tcp.srcport==2049)&&(tcp.analysis.bytes_in_flight==8948)
#   Sig2 Fast Retransmit: (tcp.srcport==2049)&&(tcp.analysis.fast_retransmission)
#   Sig1 3rd DUP ACK:     (tcp.dstport==2049)&&(tcp.analysis.duplicate_ack_num==3)
-----------------
"""

__version__ = "1.1.4"

import subprocess                          #UPDATE:1.1.3_remove_pyshark
from collections import defaultdict
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
import argparse
import sys

console = Console()

# Ports → protocols
FILE_TRANSFER_PORTS = {
    20: 'FTP Data', 21: 'FTP Control',
    22: 'SSH/SCP', 69: 'TFTP',
    80: 'HTTP', 443: 'HTTPS',
    445: 'SMB', 2049: 'NFS'
}

#UPDATE:1.1.4_signature_filters - mapping for filter column
SIGNATURE_FILTERS = {
    'Sig4 Delayed ACKs':    '(tcp.dstport==2049)&&(tcp.flags.ack==1)&&(frame.time_delta>=0.1)',
    'Sig3 Slow Start':      '(tcp.srcport==2049)&&(tcp.analysis.bytes_in_flight==8948)',
    'Sig2 Fast Retransmit': '(tcp.srcport==2049)&&(tcp.analysis.fast_retransmission)',
    'Sig1 3rd DUP ACK':     '(tcp.dstport==2049)&&(tcp.analysis.duplicate_ack_num==3)'
}

def analyze_filetransfer(pcap_file):
    # horizontal break 
    console.rule("[bold yellow]– NFS Analysis START –[/bold yellow]")
    # Counters
    total_packets = 0
    protocol_counts = defaultdict(int)
    pair_counts = defaultdict(int)
    continuation_count = 0

    sig_counts = {
        'Sig4 Delayed ACKs': 0,
        'Sig3 Slow Start': 0,
        'Sig2 Fast Retransmit': 0,
        'Sig1 3rd DUP ACK': 0
    }

    #UPDATE:1.1.3_tshark_integration
    tshark_cmd = [
        "tshark", "-r", str(pcap_file),
        "-T", "fields", "-E", "separator=,",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.time_delta",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "_ws.col.info",
        "-e", "tcp.flags.ack", "-e", "tcp.analysis.bytes_in_flight",
        "-e", "tcp.analysis.fast_retransmission", "-e", "tcp.analysis.duplicate_ack_num"
    ]
    try:
        proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        console.print(f"[red][!] tshark failed to start: {e}[/]")
        return

    for line in proc.stdout:
        total_packets += 1
        parts = line.rstrip().split(",", 13)
        if len(parts) < 14:
            continue

        (_, _, delta, src, dst,
         tcp_sport, tcp_dport, udp_sport, udp_dport,
         info, ack_flag, bytes_in_flight,
         fast_retx, dup_ack) = parts

        sport = int(tcp_sport) if tcp_sport.isdigit() else int(udp_sport) if udp_sport.isdigit() else None
        dport = int(tcp_dport) if tcp_dport.isdigit() else int(udp_dport) if udp_dport.isdigit() else None
        proto = FILE_TRANSFER_PORTS.get(sport) or FILE_TRANSFER_PORTS.get(dport)
        if not proto:
            continue

        protocol_counts[proto] += 1
        pair_counts[(src, dst, proto)] += 1

        #UPDATE:1.1.3_continuation_detection
        if "Continuation" in info:
            continuation_count += 1

        #UPDATE:1.1.3_signatures
        if dport == 2049 and ack_flag == "True":
            try:
                if float(delta) >= 0.1:
                    sig_counts['Sig4 Delayed ACKs'] += 1
            except ValueError:
                pass
        if sport == 2049 and bytes_in_flight.isdigit() and int(bytes_in_flight) == 8948:
            sig_counts['Sig3 Slow Start'] += 1
        if sport == 2049 and fast_retx == "True":
            sig_counts['Sig2 Fast Retransmit'] += 1
        if dport == 2049 and dup_ack == "3":
            sig_counts['Sig1 3rd DUP ACK'] += 1

    proc.stdout.close()
    proc.wait()

    console.print("\n[bold blue][*] File Transfer Traffic Summary:[/bold blue]\n")
    tbl = Table(show_lines=True, box=box.SIMPLE_HEAVY)
    tbl.add_column("Source", style="cyan")
    tbl.add_column("Destination", style="magenta")
    tbl.add_column("Protocol", style="green")
    tbl.add_column("Packets", justify="right")
    for (src, dst, proto), cnt in sorted(pair_counts.items(), key=lambda x: x[1], reverse=True):
        tbl.add_row(src, dst, proto, str(cnt))
    console.print(tbl)

    console.print("\n[bold blue][*] Protocol Usage (% of total packets):[/bold blue]\n")
    pct_tbl = Table(show_lines=False, box=box.MINIMAL)
    pct_tbl.add_column("Protocol", style="green")
    pct_tbl.add_column("Packets", justify="right")
    pct_tbl.add_column("% Total", justify="right")
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (cnt / total_packets * 100) if total_packets else 0
        pct_tbl.add_row(proto, str(cnt), f"{pct:.1f}%")
    console.print(pct_tbl)

    console.print(f"\n[bold yellow][*] Continuation frames detected:[/] {continuation_count}")

    console.print("\n[bold blue][*] NFS Signature Analysis:[/bold blue]\n")
    sig_tbl = Table(show_lines=False, box=box.MINIMAL)
    sig_tbl.add_column("Signature", style="bold")
    sig_tbl.add_column("Count", justify="right")
    #UPDATE:1.1.4_signature_filters
    sig_tbl.add_column("Filter", style="cyan")
    for sig, cnt in sig_counts.items():
        sig_tbl.add_row(sig, str(cnt), SIGNATURE_FILTERS[sig])
    console.print(sig_tbl)

    #UPDATE:1.1.4_divider
    console.rule("[bold yellow]– NFS Analysis END –[/bold yellow]")

def analyze(pcap_path):
    analyze_filetransfer(pcap_path)

def main():
    parser = argparse.ArgumentParser(description="Analyze file-transfer traffic in a PCAP.")
    parser.add_argument('-f', '--file', required=True, help="Path to PCAP file")
    args = parser.parse_args()
    analyze_filetransfer(Path(args.file))

if __name__ == "__main__":
    main()
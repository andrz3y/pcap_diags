"""
PCAP ANALYZER

NAME:       pdiag04_badpackets.py

VERSION:    1.1.6

-----------------
# BAD PACKETS
-----------------
USAGE:      python3 pdiag05_vsan_perf_checker.py  -f pcaps/session.pcap
----------------------------------
Reads a pcap file and filters for common TCP problems using Wireshark-style display filters.

Checks for:
- Retransmissions (possible congestion/loss)
- Duplicate ACKs (receiver got out-of-order segment)
- Fast retransmissions (sender detected loss quickly)
- Lost segments (Wireshark detected sequence gap)
- Connection resets (forcibly closed; app, network, or firewall)

Wireshark filters used: 
- TcpDupAck3+ (tcp.analysis.duplicate_ack_num >= 3)
- TcpRetrans(F/S) (tcp.analysis.retransmission || tcp.analysis.fast_retransmission)
- TcpOO (tcp.analysis.out_of_order)
- Pause=1+ms (frame.time_delta > 0.001)
- Pause=10+ms (frame.time_delta > 0.01)
- Pause=100+ms (frame.time_delta > 0.1)
- TcpWinFull (tcp.analysis.window_full)
- TcpZeroWin (tcp.analysis.zero_window)
- TcpStream (tcp.stream == ${tcp.stream})
- TcpCapDrops (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment)

- for vSAN analysis vmware doc used: https://www.vmware.com/docs/ts-tcp-unidir-wireshark-perf
"""

import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# -- BAD TYPES AND CORRESPONDING FILTERS --
BAD_TYPES = [
    ("Retransmission",       "tcp.analysis.retransmission"),
    ("Duplicate ACK",        "tcp.analysis.duplicate_ack"),
    ("Fast Retransmission",  "tcp.analysis.fast_retransmission"),
    ("Lost Segment",         "tcp.analysis.lost_segment"),
    ("Connection Reset",     "tcp.flags.reset==1"),
]

BAD_TYPE_EXPLANATION = {
    'Retransmission': 'Indicates possible congestion or loss',
    'Duplicate ACK': 'Receiver got out-of-order segment',
    'Fast Retransmission': 'Sender detected loss quickly',
    'Lost Segment': 'Wireshark detected sequence gap',
    'Connection Reset': 'Connection forcibly closed (reset)',
}

FIELDS = [
    'frame.time',
    'ip.src',
    'tcp.srcport',
    'ip.dst',
    'tcp.dstport',
    '_ws.col.Protocol',
    'tcp.flags',
    'tcp.window_size_value'
]

def run_tshark(pcap_file, display_filter):
    """
    Runs tshark with the given filter, returns a list of packets (each as a dict with FIELDS).
    """
    cmd = [
        'tshark', '-r', str(pcap_file), '-Y', display_filter, '-T', 'fields'
    ]
    for field in FIELDS:
        cmd += ['-e', field]
    cmd += ['-E', 'separator=|', '-E', 'quote=d', '-E', 'occurrence=f']
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    packets = []
    for line in lines:
        # Parse, but be robust if some fields missing
        parts = [p.strip('"') for p in line.split('|')]
        while len(parts) < len(FIELDS):
            parts.append('-')
        pkt = dict(zip(FIELDS, parts))
        packets.append(pkt)
    return packets

def decode_tcp_flags(hex_val):
    """
    Given a hex string (e.g. '0x0018'), returns decoded TCP flag names (SYN, ACK, etc).
    """
    try:
        if not hex_val or not hex_val.startswith('0x'):
            return '-'
        flags_int = int(hex_val, 16)
        flags = []
        if flags_int & 0x01: flags.append('FIN')
        if flags_int & 0x02: flags.append('SYN')
        if flags_int & 0x04: flags.append('RST')
        if flags_int & 0x08: flags.append('PSH')
        if flags_int & 0x10: flags.append('ACK')
        if flags_int & 0x20: flags.append('URG')
        if flags_int & 0x40: flags.append('ECE')
        if flags_int & 0x80: flags.append('CWR')
        return ','.join(flags) if flags else '-'
    except Exception:
        return '-'

def analyze_badpackets(pcap_file):
    """
    For each bad packet type, runs tshark, parses results, tags each packet.
    Returns: all_bad_packets (list of dicts, with 'bad_type' attached), total_packets (int)
    """
    console = Console()
    all_bad_packets = []
    unique_keys = set()  # For deduplication

    # -- Get total packet count with minimal pass
    total_packets = 0
    try:
        cmd_count = ['tshark', '-r', str(pcap_file), '-T', 'fields', '-e', 'frame.number']
        total_packets = sum(1 for _ in subprocess.run(cmd_count, capture_output=True, text=True).stdout.splitlines())
    except Exception as e:
        console.print(f"[red]Error reading total packets: {e}[/]")
        total_packets = 0

    # -- For each bad type, run tshark, tag, add
    for bad_type, tshark_filter in BAD_TYPES:
        packets = run_tshark(pcap_file, tshark_filter)
        for pkt in packets:
            # Create a unique key to avoid duplicates (by time+src+dst+sport+dport)
            key = (pkt['frame.time'], pkt['ip.src'], pkt['ip.dst'], pkt['tcp.srcport'], pkt['tcp.dstport'])
            if key in unique_keys:
                continue
            unique_keys.add(key)
            pkt['bad_type'] = bad_type
            all_bad_packets.append(pkt)
    return all_bad_packets, total_packets

def print_bad_summary(pcap_file, bad_packets, total_packets):
    """
    Print a nice blue panel, the summary table, and Wireshark filter.
    """
    console = Console()
    # Blue panel at top
    panel_msg = f"[*] Running Bad Packet Checker...\n[*] PCAP file: {pcap_file}"
    console.print(Panel(panel_msg, expand=False, border_style="blue"))

    # Print filter logic and totals
    console.print("[bold]Filters used:[/]")
    for desc, expl in BAD_TYPE_EXPLANATION.items():
        console.print(f" - [cyan]{desc}[/]: {expl}")
    console.print()
    bad_count = len(bad_packets)
    percent_bad = (bad_count / total_packets * 100) if total_packets else 0
    console.print(f"[bold]Total packets in capture:[/] {total_packets}")
    console.print(f"[bold red]Bad packets found:[/] {bad_count}  ([yellow]{percent_bad:.2f}%[/] of all packets)\n")

    if not bad_packets:
        console.print("[green]No bad packets found. :)[/]")
        return

    # Sort by time (as string, so close enough for output order)
    sorted_bad = sorted(bad_packets, key=lambda p: p['frame.time'])

    table = Table(title="Bad Packet Summary", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Time", style="dim", width=32)
    table.add_column("Src IP", style="cyan")
    table.add_column("SPort", justify="right")
    table.add_column("Dst IP", style="magenta")
    table.add_column("DPort", justify="right")
    table.add_column("Proto", style="green")
    table.add_column("Bad Type", style="bold", justify="center")
    table.add_column("TCP Flags (hex)", style="bold")
    table.add_column("TCP Flags (decoded)", style="yellow")
    table.add_column("WinSize", justify="right")

    # Color by type
    type_color = {
        'Retransmission': "red",
        'Duplicate ACK': "yellow",
        'Fast Retransmission': "red",
        'Lost Segment': "yellow",
        'Connection Reset': "bright_red",
    }

    for pkt in sorted_bad:
        style = type_color.get(pkt['bad_type'], "white")
        tcp_flags = pkt.get('tcp.flags', '-')
        decoded_flags = decode_tcp_flags(tcp_flags)
        table.add_row(
            pkt.get('frame.time', '-'),
            pkt.get('ip.src', '-'),
            pkt.get('tcp.srcport', '-'),
            pkt.get('ip.dst', '-'),
            pkt.get('tcp.dstport', '-'),
            pkt.get('_ws.col.Protocol', '-'),
            f"[{style}]{pkt['bad_type']}[/{style}]",
            tcp_flags,
            decoded_flags,
            pkt.get('tcp.window_size_value', '-')
        )

    console.print(table)

    # Print Wireshark filter for user reference
    ws_filter = " || ".join([f for _, f in BAD_TYPES])
    console.print(f"\n[bold cyan][*] Wireshark Filter: {ws_filter} [*][/]\n")

# --- MODULE INTERFACE FOR MENU ---
def analyze(pcap_file):
    """
    Entry point for menu usage: analyze the file and print the summary.
    Only call this from your menu handler!
    """
    bad_packets, total_packets = analyze_badpackets(pcap_file)
    print_bad_summary(pcap_file, bad_packets, total_packets)

# --- STANDALONE USAGE ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze bad traffic in a PCAP file (FAST, tshark-based).")
    parser.add_argument('-f', '--file', help="Path to the PCAP file to be analyzed")
    args = parser.parse_args()
    if args.file:
        analyze(args.file)
    else:
        print("This module can also be used with other scripts.")

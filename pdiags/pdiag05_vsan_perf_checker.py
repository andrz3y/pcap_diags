"""
PCAP ANALYZER 

NAME:       pdiag05_vsan_perf_checker.py 

VERSION:    1.1.6

--------------------------
# VSAN PERFORMANCE CHECKER   
--------------------------
USAGE:      python3 pdiag05_vsan_perf_checker.py  -f pcaps/session.pcap
----------------------------------
VSAN 
- vSAN itself uses management communication on 12321 and is separated network by default
- So we look for packets with 12321 port, endpoints, 
- vSAN performance usually is affected by network performance indicators, like: congestion, retransmits, so we want to find them also 
----------------------------------
HOW WE FIND IT:
- vSAN filter:              tcp.port == 12321 or udp.port == 12321
- congestion filter         tcp.analysis.ack_rtt > 500
- retransmits filter:       tcp.analysis.retransmission or tcp.analysis.duplicate_ack


---> https://www.vmware.com/docs/ts-tcp-unidir-wireshark-perf


"""

import pyshark
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import argparse

console = Console()

def analyze(pcap_file):
    """
    Main entry point for menu integration.
    """
    # horizontal line: 
    console.rule("[bold yellow]– vSAN Analysis START –[/bold yellow]")

    # Print panel at the start
    console.print(Panel.fit(f"[*] Starting vSAN analysis on pcap: [bold]{pcap_file}[/]"))

    # [1] vSAN general
    vsan_packets = []
    vsan_filter = "tcp.port == 12321 or udp.port == 12321"
    capture = pyshark.FileCapture(str(pcap_file), display_filter=vsan_filter)

    try:
        for packet in capture:
            packet_info = {
                'time': packet.sniff_time,
                'source': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                'destination': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                'protocol': packet.highest_layer
            }
            vsan_packets.append(packet_info)
    except Exception as e:
        console.print(f"[red]Error processing general vSAN packets: {e}[/red]")
    finally:
        capture.close()

    # [2] Retransmit analysis
    vsan_retransmit_packets = []
    vsan_filter_retransmits = "(tcp.analysis.retransmission or tcp.analysis.duplicate_ack)"
    capture2 = pyshark.FileCapture(str(pcap_file), display_filter=vsan_filter_retransmits)
    try:
        for packet in capture2:
            packet_info = {
                'time': packet.sniff_time,
                'source': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                'destination': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                'sequence_number': packet.tcp.seq if hasattr(packet, 'tcp') else 'N/A',
                'ack_number': packet.tcp.ack if hasattr(packet, 'tcp') else 'N/A',
                'flags': packet.tcp.flags if hasattr(packet, 'tcp') else 'N/A',
                'length': packet.length
            }
            vsan_retransmit_packets.append(packet_info)
    except Exception as e:
        console.print(f"[red]Error processing retransmit vSAN packets: {e}[/red]")
    finally:
        capture2.close()

    # [3] Latency analysis
    vsan_latency_packets = []
    vsan_filter_latency = "(tcp.analysis.ack_rtt > 500)"
    capture3 = pyshark.FileCapture(str(pcap_file), display_filter=vsan_filter_latency)
    try:
        for packet in capture3:
            packet_info = {
                'time': packet.sniff_time,
                'source': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                'destination': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                'protocol': packet.highest_layer,
                'ack_rtt': packet.tcp.analysis_ack_rtt if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'analysis_ack_rtt') else 'N/A',
                'length': packet.length
            }
            vsan_latency_packets.append(packet_info)
    except Exception as e:
        console.print(f"[red]Error processing latency vSAN packets: {e}[/red]")
    finally:
        capture3.close()

    # Output summary
    print_vsan_summary(vsan_packets, vsan_retransmit_packets, vsan_latency_packets)

def print_vsan_summary(vsan_packets, vsan_retransmit_packets, vsan_latency_packets):
    # Stage 1: General vSAN summary
    table = Table(title="General vSAN Packets", show_lines=False)
    table.add_column("Time")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="magenta")
    table.add_column("Protocol")
    for pkt in vsan_packets[:15]:  # Show up to 15 rows
        table.add_row(str(pkt['time']), pkt['source'], pkt['destination'], pkt['protocol'])
    console.print(table)
    console.print(f"[bold]Total vSAN packets:[/] {len(vsan_packets)}")

    unique_sources = {p['source'] for p in vsan_packets}
    unique_dests = {p['destination'] for p in vsan_packets}
    console.print(f"Unique source IPs: [bold cyan]{', '.join(unique_sources)}[/]")
    console.print(f"Unique destination IPs: [bold magenta]{', '.join(unique_dests)}[/]")

    if vsan_packets:
        console.print(f"Capture start: {vsan_packets[0]['time']}")
        console.print(f"Capture end:   {vsan_packets[-1]['time']}")

    # Total packets per source/dest (print top 5)
    src_count = {}
    dest_count = {}
    for pkt in vsan_packets:
        src_count[pkt['source']] = src_count.get(pkt['source'], 0) + 1
        dest_count[pkt['destination']] = dest_count.get(pkt['destination'], 0) + 1

    top_src = sorted(src_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_dest = sorted(dest_count.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_src:
        console.print("[bold]Top 5 Source IPs by packet count:[/]")
        for src, cnt in top_src:
            console.print(f"  {src}: {cnt}")
    if top_dest:
        console.print("[bold]Top 5 Destination IPs by packet count:[/]")
        for dest, cnt in top_dest:
            console.print(f"  {dest}: {cnt}")

    # Stage 2: Retransmits
    table2 = Table(title="Retransmit vSAN Packets", show_lines=False)
    table2.add_column("Time")
    table2.add_column("Source", style="cyan")
    table2.add_column("Destination", style="magenta")
    table2.add_column("Seq", justify="right")
    table2.add_column("Ack", justify="right")
    table2.add_column("Flags")
    table2.add_column("Length", justify="right")
    for pkt in vsan_retransmit_packets[:15]:  # Show up to 15 rows
        table2.add_row(
            str(pkt['time']),
            pkt['source'],
            pkt['destination'],
            str(pkt['sequence_number']),
            str(pkt['ack_number']),
            str(pkt['flags']),
            str(pkt['length']),
        )
    console.print(table2)
    console.print(f"[yellow]Total retransmit/dup-ack packets: {len(vsan_retransmit_packets)}[/yellow]")
    pct = (len(vsan_retransmit_packets) / len(vsan_packets) * 100) if vsan_packets else 0
    console.print(f"Percentage of retransmit packets: [bold yellow]{pct:.2f}%[/]")

    # Stage 3: Latency
    table3 = Table(title="High-Latency vSAN Packets (RTT > 500ms)", show_lines=False)
    table3.add_column("Time")
    table3.add_column("Source", style="cyan")
    table3.add_column("Destination", style="magenta")
    table3.add_column("Protocol")
    table3.add_column("ACK RTT (ms)", justify="right")
    table3.add_column("Length", justify="right")
    for pkt in vsan_latency_packets[:15]:  # Show up to 15 rows
        table3.add_row(
            str(pkt['time']),
            pkt['source'],
            pkt['destination'],
            pkt['protocol'],
            str(pkt['ack_rtt']),
            str(pkt['length']),
        )
    console.print(table3)
    console.print(f"[red]Total high-latency packets: {len(vsan_latency_packets)}[/red]")
    pct2 = (len(vsan_latency_packets) / len(vsan_packets) * 100) if vsan_packets else 0
    console.print(f"Percentage of high-latency packets: [bold red]{pct2:.2f}%[/]")

    # Info for Wireshark filter
    console.print("\n[dim]Wireshark filters used:")
    console.print("  [cyan]tcp.port == 12321 or udp.port == 12321[/cyan]")
    console.print("  [yellow]tcp.analysis.retransmission or tcp.analysis.duplicate_ack[/yellow]")
    console.print("  [red]tcp.analysis.ack_rtt > 500[/red]\n")

    # horizontal end line 
    console.rule("[bold yellow]– vSAN Analysis END –[/bold yellow]")


def main():
    parser = argparse.ArgumentParser(description="Analyze vSAN-related traffic in a PCAP file.")
    parser.add_argument('-f', '--file', help="Path to the PCAP file to be analyzed")
    args = parser.parse_args()

    if args.file:
        analyze(args.file)
    else:
        print("Please provide a valid PCAP file using the -f or --file option.")

if __name__ == "__main__":
    main()

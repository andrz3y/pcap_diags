"""
PCAP ANALYZER 

NAME:       pdiag01_conversation_analyzer.py     

VERSION:    1.1.4

----------------- 

- Reads a PCAP file via tshark
- Finds all host-to-host "conversations"
- For each: Source IP, Dest IP, Protocol, Src Port, Dst Port, Packet Count, Bytes

------------------------
# READ PACKETS FROM PCAP   
------------------------
USAGE:          python3 pdiags/conversation_analyzer.py <path_to_pcap>
"""

# --- Imports ---
import subprocess                     # for tshark integration
from collections import defaultdict   # for auto-initializing dictionary values
from pathlib import Path              # for clean file paths
from rich.console import Console      # pretty print
from rich.table import Table          # pretty table output
import sys

console = Console()

#UPDATE:1.1.4_function_entry – renamed to match pcap_analyzer invocation
def analyze(pcap_file):
    console.print(f"\n[bold blue]* Analyzing conversations in:[/] {pcap_file.name}\n")

    conversations = defaultdict(lambda: {"packet_count": 0, "byte_count": 0})

    tshark_cmd = [
        "tshark",
        "-r", str(pcap_file),
        "-T", "fields",
        "-E", "separator=,",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len"
    ]
    try:
        proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        console.print(f"[red][!] Failed to start tshark: {e}[/]")
        return

    for line in proc.stdout:
        fields = line.strip().split(",")
        if len(fields) != 8:
            continue
        src, dst, proto, tcp_sport, tcp_dport, udp_sport, udp_dport, length = fields
        if not src or not dst:
            continue

        if proto.upper() == "TCP":
            sport, dport = tcp_sport, tcp_dport
        elif proto.upper() == "UDP":
            sport, dport = udp_sport, udp_dport
        else:
            sport = dport = ""

        key = (src, dst, proto, sport, dport)
        conversations[key]["packet_count"] += 1
        try:
            conversations[key]["byte_count"] += int(length)
        except ValueError:
            pass

    proc.stdout.close()
    proc.wait()

    rows = []
    for (src, dst, proto, sport, dport), stats in conversations.items():
        rows.append([src, dst, proto, sport, dport, stats["packet_count"], stats["byte_count"]])

    if not rows:
        console.print("[yellow][!] No IP-based conversations found in this capture.[/]")
        return

    table = Table(title="Conversation Summary", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="magenta")
    table.add_column("Proto", style="green")
    table.add_column("SrcPort", justify="right")
    table.add_column("DstPort", justify="right")
    table.add_column("Packets", justify="right", style="bold")
    table.add_column("Bytes", justify="right")

    for row in rows:
        table.add_row(*[str(cell) for cell in row])

    console.print(table)
    console.print(f"[bold green]\n[*] Total unique conversations: {len(rows)}\n[/]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(f"\n[red][!] Usage: python3 conversation_analyzer.py <pcap_file>[/]")
    else:
        analyze(Path(sys.argv[1]))

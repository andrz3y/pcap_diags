"""
PCAP ANALYZER 

NAME:       pdiag02_endhost_general.py 

VERSION:    1.1.3

-----------------------
# END HOST GENERAL INFO   
-----------------------
USAGE:      python3 pdiag02_endhost_general.py  -f pcaps/session.pcap

- show top talkers
- traffic in and out per host 
- port usage 
"""

# --- Imports ---
import subprocess                       
from rich.console import Console
from rich.table import Table
from collections import defaultdict
from pathlib import Path
import ipaddress
import sys

# ---- Port to Service Lookup (basic) ----
PORT_SERVICES = {
    53:  'DNS', 80:  'HTTP', 443: 'HTTPS', 21:  'FTP', 22:  'SSH', 23:  'TELNET',
    25:  'SMTP', 110: 'POP3', 143: 'IMAP', 123: 'NTP', 445: 'SMB', 389: 'LDAP',
    3306: 'MySQL', 5432: 'Postgres', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-ALT'
}

console = Console()

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def analyze(pcap_path):
    console.print(f"\n[bold blue]* Analyzing End Hosts in:[/] {pcap_path}\n")

    hosts = set()
    external_hosts = set()
    host_stats = defaultdict(lambda: {'sent_pkts': 0, 'recv_pkts': 0, 'sent_bytes': 0, 'recv_bytes': 0})
    port_usage = defaultdict(lambda: defaultdict(lambda: {'proto': '', 'pkts': 0, 'bytes': 0}))
    tcp_syns = defaultdict(int)
    tcp_synacks = defaultdict(int)
    tcp_connections = set()

    #UPDATE:1.1.3_tshark_integration - use tshark for fast field extraction
    tshark_cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-T", "fields",
        "-E", "separator=,",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
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
        parts = line.strip().split(",")
        if len(parts) != 9:
            continue
        src, dst, proto, tcp_sport, tcp_dport, tcp_flags, udp_sport, udp_dport, length = parts
        if not src or not dst:
            continue

        # Determine protocol and ports, plus SYN/SYN-ACK
        if proto.upper() == "TCP":
            sport = int(tcp_sport) if tcp_sport.isdigit() else ''
            dport = int(tcp_dport) if tcp_dport.isdigit() else ''
            # parse flags (supports hex or decimal)
            try:
                flags_int = int(tcp_flags, 0)
            except Exception:
                flags_int = 0
            syn = bool(flags_int & 0x02)
            ack = bool(flags_int & 0x10)
            if syn and not ack:
                tcp_syns[(src, dst, sport, dport)] += 1
            elif syn and ack:
                tcp_synacks[(dst, src, dport, sport)] += 1
            if ((src, dst, sport, dport) in tcp_syns and
                (src, dst, sport, dport) in tcp_synacks):
                tcp_connections.add((src, dst, sport, dport))
        elif proto.upper() == "UDP":
            sport = int(udp_sport) if udp_sport.isdigit() else ''
            dport = int(udp_dport) if udp_dport.isdigit() else ''
        elif proto.upper() == "ICMP":
            sport = ''
            dport = ''
        else:
            sport = ''
            dport = ''

        # length parsing
        try:
            size = int(length)
        except ValueError:
            size = 0

        # classify hosts
        if is_private_ip(src):
            hosts.add(src)
        else:
            external_hosts.add(src)
        if is_private_ip(dst):
            hosts.add(dst)
        else:
            external_hosts.add(dst)

        # traffic stats
        host_stats[src]['sent_pkts'] += 1
        host_stats[src]['sent_bytes'] += size
        host_stats[dst]['recv_pkts'] += 1
        host_stats[dst]['recv_bytes'] += size

        # port usage
        if sport != '':
            port_usage[src][(proto, sport)]['proto'] = proto
            port_usage[src][(proto, sport)]['pkts'] += 1
            port_usage[src][(proto, sport)]['bytes'] += size
        if dport != '':
            port_usage[dst][(proto, dport)]['proto'] = proto
            port_usage[dst][(proto, dport)]['pkts'] += 1
            port_usage[dst][(proto, dport)]['bytes'] += size

    proc.stdout.close()
    proc.wait()

    # ---- Output Tables ----

    # 1. Private Hosts
    if hosts:
        table = Table(title="Private (Local) Hosts", show_lines=True)
        table.add_column("Host", style="bold")
        table.add_column("Packets Sent")
        table.add_column("Packets Recv")
        table.add_column("Bytes Sent")
        table.add_column("Bytes Recv")
        for host in sorted(hosts):
            s = host_stats[host]
            table.add_row(
                host,
                str(s['sent_pkts']),
                str(s['recv_pkts']),
                str(s['sent_bytes']),
                str(s['recv_bytes'])
            )
        console.print(table)
    else:
        console.print("[yellow][!] No private hosts found.[/]")

    # 2. External Hosts
    if external_hosts:
        table = Table(title="External Hosts", show_lines=True)
        table.add_column("Host", style="bold cyan")
        table.add_column("Packets Sent")
        table.add_column("Packets Recv")
        table.add_column("Bytes Sent")
        table.add_column("Bytes Recv")
        for host in sorted(external_hosts):
            s = host_stats[host]
            table.add_row(
                host,
                str(s['sent_pkts']),
                str(s['recv_pkts']),
                str(s['sent_bytes']),
                str(s['recv_bytes'])
            )
        console.print(table)
    else:
        console.print("[green][!] No external hosts found.[/]")

    # 3. Top Talkers
    table = Table(title="Top Talkers", show_lines=True)
    table.add_column("Host", style="bold magenta")
    table.add_column("Total Bytes Sent", justify="right")
    table.add_column("Total Bytes Recv", justify="right")
    sorted_hosts = sorted(
        host_stats.items(),
        key=lambda kv: (kv[1]['sent_bytes'], kv[1]['recv_bytes']),
        reverse=True
    )
    for host, s in sorted_hosts[:15]:
        table.add_row(host, str(s['sent_bytes']), str(s['recv_bytes']))
    console.print(table)

    # 4. Per-Host Port Usage (top 5 hosts)
    for host, ports in list(port_usage.items())[:5]:
        table = Table(title=f"Port/Proto Usage for {host}", show_lines=False)
        table.add_column("Proto")
        table.add_column("Port", justify="right")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Service", style="cyan")
        for (proto, port), stats in sorted(ports.items(), key=lambda kv: kv[1]['pkts'], reverse=True):
            svc = PORT_SERVICES.get(port, "")
            table.add_row(
                proto,
                str(port),
                str(stats['pkts']),
                str(stats['bytes']),
                svc
            )
        console.print(table)

    # 5. TCP SYN/Scan Table
    scan_table = Table(title="TCP SYN/Scan Analysis (Possible Scans)", show_lines=True)
    scan_table.add_column("Src Host")
    scan_table.add_column("Dst Host")
    scan_table.add_column("Src Port")
    scan_table.add_column("Dst Port")
    scan_table.add_column("SYNs")
    scan_table.add_column("SYN-ACKs")
    scan_table.add_column("Completed Conn", style="green")
    scan_table.add_column("Likely Scan?", style="red")
    for key in tcp_syns:
        syns = tcp_syns.get(key, 0)
        synacks = tcp_synacks.get(key, 0)
        completed = syns > 0 and synacks > 0
        likely_scan = syns > 0 and synacks == 0
        scan_table.add_row(
            key[0], key[1], str(key[2]), str(key[3]),
            str(syns), str(synacks),
            "Yes" if completed else "",
            "Yes" if likely_scan else "",
        )
    if scan_table.row_count > 0:
        console.print(scan_table)
    else:
        console.print("[green][!] No TCP SYN/Scan activity detected.[/]")

    console.print("[bold green]\nEnd Host General analysis complete![/]\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 endhost_general.py <path_to_pcap>")
    else:
        analyze(Path(sys.argv[1]))

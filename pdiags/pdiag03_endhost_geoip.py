"""
PCAP ANALYZER 

NAME:       pdiag03_endhost_geoip.py

VERSION:    1.1.6

-----------------------
# END HOST GENERAL INFO   
-----------------------
USAGE:      python3 pdiag03_endhost_geoip.py  -f pcaps/session.pcap

- summarize unique hosts (src and dst)
- display GeoIP info about each of the hosts 
- check if host IP is private, reserved or ISP/organization
- check pcap for TCP flags indicating port scans
----------------------------------
# PREREQS:

- GeoIP installed:              sudo apt install python3-geoip2
- Latest geoDB downloaded:      https://www.maxmind.com/en/accounts/1067801/geoip/downloads
----------------------------------
"""

__version__ = "1.1.6"

# IMPORTS 
import subprocess                         #UPDATE:1.1.4_tshark_integration
import datetime                           #UPDATE:1.1.4_timestamp_parsing
import geoip2.database
import ipaddress
import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def get_geoip_reader():
    root_dir = Path(__file__).parent.parent.resolve()
    geoip_path = root_dir / "geoipdb" / "GeoLite2-City.mmdb"
    if not geoip_path.exists():
        console.print(f"[red][!] GeoIP DB not found: {geoip_path}[/]")
        return None
    try:
        return geoip2.database.Reader(str(geoip_path))
    except Exception as e:
        console.print(f"[red][!] Failed to load GeoIP DB: {e}[/]")
        return None

def analyze_pcap(file_path):
    unique_ips = set()
    arp_requests = {}
    arp_replies = set()
    icmp_count = 0
    mdns_count = 0
    scan_signatures = {"FIN": 0, "NULL": 0, "XMAS": 0}
    packet_count = 0
    first_time = last_time = None

    #UPDATE:1.1.4_tshark_integration
    tshark_cmd = [
        "tshark", "-r", str(file_path), "-T", "fields", "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
        "-e", "tcp.flags", "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "frame.len",
        "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4", "-e", "arp.opcode"
    ]
    try:
        proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        console.print(f"[red][!] Failed to start tshark: {e}[/]")
        return set(), None, None, 0, 0, 0, 0, scan_signatures

    for line in proc.stdout:
        packet_count += 1
        parts = line.strip().split(",")
        if len(parts) < 13:
            continue

        #UPDATE:1.1.4_timestamp_parsing
        ts = parts[0]
        try:
            dt = datetime.datetime.fromtimestamp(float(ts))
        except Exception:
            dt = None
        if dt:
            if first_time is None:
                first_time = dt
            last_time = dt

        src, dst, proto = parts[1], parts[2], parts[3]
        tcp_flags, tcp_sport, tcp_dport = parts[4], parts[5], parts[6]
        udp_sport, udp_dport = parts[7], parts[8]
        length = parts[9]
        arp_src, arp_dst, arp_op = parts[10], parts[11], parts[12]

        if src:
            unique_ips.add(src)
        if dst:
            unique_ips.add(dst)

        #UPDATE:1.1.4_icmp_mdns_count
        if proto.upper() == "ICMP":
            icmp_count += 1
        elif proto.upper() == "MDNS":
            mdns_count += 1

        # TCP scan signatures
        if proto.upper() == "TCP" and tcp_flags:
            try:
                flags = int(tcp_flags, 0)
            except Exception:
                flags = 0
            if flags == 0x001:
                scan_signatures["FIN"] += 1
            elif flags == 0x000:
                scan_signatures["NULL"] += 1
            elif flags == 0x029:
                scan_signatures["XMAS"] += 1

        #UPDATE:1.1.5_arp_summary
        if arp_op == '1':
            arp_requests[(arp_src, arp_dst)] = arp_requests.get((arp_src, arp_dst), 0) + 1
        elif arp_op == '2':
            arp_replies.add((arp_src, arp_dst))

    proc.stdout.close()
    proc.wait()

    unresolved_count = sum(1 for req in arp_requests if req not in arp_replies)
    return unique_ips, first_time, last_time, packet_count, unresolved_count, icmp_count, mdns_count, scan_signatures

def get_geoip_info(ip, geoip_reader):
    try:
        ip_obj = ipaddress.ip_address(ip)
        base = {
            'private': ip_obj.is_private,
            'reserved': ip_obj.is_reserved,
            'global': ip_obj.is_global,
            'loopback': ip_obj.is_loopback
        }
        if not geoip_reader:
            return {**base,
                'city': "Unknown", 'country': "Unknown", 'county': "Unknown",
                'region_code': "", 'postal_code': "Unknown",
                'latitude': "", 'longitude': "",
                'is_anonymous_proxy': "", 'is_satellite_provider': ""
            }
        resp = geoip_reader.city(ip)
        return {**base,
            'city': resp.city.name or "Unknown",
            'country': resp.country.name or "Unknown",
            'county': resp.subdivisions.most_specific.name or "Unknown",
            'region_code': resp.subdivisions.most_specific.iso_code or "",
            'postal_code': resp.postal.code or "Unknown",
            'latitude': str(resp.location.latitude) if resp.location.latitude else "",
            'longitude': str(resp.location.longitude) if resp.location.longitude else "",
            'is_anonymous_proxy': str(getattr(resp.traits, "is_anonymous_proxy", "")),
            'is_satellite_provider': str(getattr(resp.traits, "is_satellite_provider", ""))
        }
    except Exception:
        return {
            'private': False, 'reserved': False, 'global': False, 'loopback': False,
            'city': "Unknown", 'country': "Unknown", 'county': "Unknown",
            'region_code': "", 'postal_code': "Unknown",
            'latitude': "", 'longitude': "",
            'is_anonymous_proxy': "", 'is_satellite_provider': ""
        }

def is_multicast(ip):
    try:
        return ipaddress.ip_address(ip).is_multicast
    except Exception:
        return False

def print_summary(filename, host_info, first_packet_time, last_packet_time,
                  packet_count, unresolved_count,
                  icmp_count, mdns_count, scan_signatures, geoip_reader):
    console.print("\n[bold blue][*] PCAP Summary:[/bold blue]\n")
    console.print(f"    Analyzing file:     [green]{filename}[/green]")
    console.print(f"    PCAP start time:    {first_packet_time}")
    console.print(f"    PCAP end time:      {last_packet_time}")
    console.print(f"    PCAP total packets: {packet_count}")

    #UPDATE:1.1.5_arp_summary
    console.print(f"[bold yellow][*] Unresolved ARP requests:[/] {unresolved_count}")

    console.print(f"\n[bold yellow][*] ICMP Packet Count:[/] {icmp_count}")
    console.print(f"[bold yellow][*] mDNS Packet Count:[/] {mdns_count}")

    scan_tbl = Table(title="TCP Scan Signatures", box=box.SIMPLE)
    scan_tbl.add_column("Type", style="bold")
    scan_tbl.add_column("Count", justify="right")
    for stype, cnt in scan_signatures.items():
        scan_tbl.add_row(stype, str(cnt))
    console.print(scan_tbl)

    tbl = Table(title="Unique Hosts in PCAP", show_lines=True, box=box.SQUARE)
    tbl.add_column("IP Address", style="cyan")
    tbl.add_column("Private", style="bold green")
    tbl.add_column("Reserved")
    tbl.add_column("Global")
    tbl.add_column("Loopback")
    tbl.add_column("Multicast")
    tbl.add_column("City")
    tbl.add_column("Country")
    tbl.add_column("County")
    tbl.add_column("RegionCode")
    tbl.add_column("Postal Code")
    tbl.add_column("Latitude")
    tbl.add_column("Longitude")
    tbl.add_column("AnonProxy")
    tbl.add_column("Satellite")

    for ip in sorted(host_info):
        info = get_geoip_info(ip, geoip_reader)
        tbl.add_row(
            ip,
            "[green]True[/green]" if info['private'] else "[yellow]False[/yellow]",
            str(info['reserved']),
            str(info['global']),
            str(info['loopback']),
            "Yes" if is_multicast(ip) else "No",
            info['city'], info['country'], info['county'],
            info['region_code'], info['postal_code'],
            info['latitude'], info['longitude'],
            info['is_anonymous_proxy'], info['is_satellite_provider']
        )
    console.print(tbl)
    console.print("[bold green]\nEnd Host GeoIP analysis complete![/]\n")

def analyze(pcap_path):
    geoip_reader = get_geoip_reader()
    (unique_ips, first_time, last_time,
     packet_count, unresolved_count,
     icmp_count, mdns_count,
     scan_signatures) = analyze_pcap(pcap_path)
    print_summary(pcap_path, unique_ips, first_time, last_time,
                  packet_count, unresolved_count,
                  icmp_count, mdns_count, scan_signatures, geoip_reader)

def main():
    parser = argparse.ArgumentParser(description="Analyze hosts and show GeoIP info.")
    parser.add_argument('-f', '--file', help="PCAP file path")
    args = parser.parse_args()
    if args.file:
        analyze(args.file)
    else:
        print("Usage: python3 pdiag03_endhost_geoip.py -f <pcap_path>")

if __name__ == "__main__":
    main()

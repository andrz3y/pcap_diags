"""
PCAP ANALYZER 

NAME:       pdiag09_read_everypcap.py 

VERSION:    1.1.6

------------------------
# READ PACKETS FROM PCAP   
------------------------
USAGE:      python3 pdiag09_read_everypcap.py  pcaps/session.pcap
-----------------------------------------------------------------
- using tshark to stream packets 
- read 100 packets at once before continue/exit 
"""
 

import subprocess                              
from pathlib import Path
import sys
from rich.console import Console                

__version__ = "1.1.6"

#
# COLOR FILTERS 
#
style_map = {
    "ARP":    "yellow",
    "ICMP":   "yellow",
    "ICMPv6": "yellow",
    "TCP":    "cyan",
    "UDP":    "magenta",
    "HTTP":   "green",
    "DNS":    "bright_blue",
    "SMB":    "bright_green",
    "NFS":    "bright_magenta",
    "DHCP":   "yellow",
    "NTP":    "yellow",
    "DCERPC": "green",
    "ESP":    "green",
    "AH":     "green",
    "OSPF":   "red",
    "BGP":    "red",
    "EIGRP":  "red",
    "IGMP":   "red",
    "HSRP":   "red",
    "VRRP":   "red",
    "CARP":   "red",
    "STP":    "red",
    "SCTP":   "red",
}

console = Console()                             


def analyze(pcap_path):
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        print(f"[!] PCAP file not found: {pcap_file}")
        return

    # count_packets - count total packets first
    count_cmd = ["tshark", "-r", str(pcap_file), "-T", "fields", "-e", "frame.number"]
    try:
        proc_count = subprocess.Popen(count_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except Exception as e:
        print(f"[!] Failed to start tshark for counting: {e}")
        return
    total = sum(1 for _ in proc_count.stdout)
    proc_count.stdout.close()
    proc_count.wait()

    print("="*75)
    print(f"[*] {pcap_file.name} has {total} packets.")
    print("Choose how to read it:")
    print("[1] Paginate by 100 (print 100, wait for Enter/'q', repeat)")
    print("[2] Read all at once")
    print("[3] Back to module menu")
    choice = input("Enter your choice (1/2/3): ").strip()
    print("="*75)

    if choice == '1':
        mode = 'paginate'
    elif choice == '2':
        mode = 'all'
    else:
        print("[*] Returning to module menu...\n")
        return

    cmd = ["tshark", "-r", str(pcap_file)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        print(f"[!] Failed to start tshark: {e}")
        return

    count = 0
    page_size = 100

    print(f"\n[*] Streaming packets from {pcap_file.name} ({'paginated' if mode=='paginate' else 'full dump'})\n")

    for line in proc.stdout:
        line = line.rstrip()
        count += 1

        # color filters - extract protocol and colorize
        parts = line.split()
        proto = parts[5] if len(parts) > 5 else None
        style = style_map.get(proto)
        # 
        # IPYTHON CHECK: 
        # first = !tshark -r pcaps/session.pcap -c 1
        # 
        # line = first[0]
        # for idx, token in enumerate(line.split()):
        #     print(idx, token)
        #
        # parts[5] is the protocol


        console.print(line, style=style) if style else print(line)

        if mode == 'paginate' and count % page_size == 0:
            print(f"-- Printed {count} of {total} packets --")
            ans = input("Press Enter to continue, or 'q' to quit: ").strip().lower()
            if ans == 'q':
                break

        if mode == 'all' and count >= total:
            break

    proc.stdout.close()
    proc.wait()

    print(f"\n[+] Done. Printed {count} packets.\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pdiag09_read_everypcap.py <path_to_pcap>")
    else:
        analyze(sys.argv[1])

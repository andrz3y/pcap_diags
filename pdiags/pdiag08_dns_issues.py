"""
PCAP ANALYZER 

NAME:       pdiag08_dns_issues.py

VERSION:    1.1.6

------------------
DNS Issues Checker
------------------
USAGE:          python3 pdiag08_dns_issues.py pcaps/session.pcap 
------------------
- using tshark to stream packets 
- finds DNS queries that never got a response
- Counts DNS response codes (NXDOMAIN, SERVFAIL, etc.)

"""

#UPDATE:1.1.6_tshark_dns - use tshark to stream DNS fields
import subprocess
from collections import defaultdict
from pathlib import Path
import sys

from rich.console import Console
from rich.table import Table

__version__ = "1.1.6"

console = Console()

def analyze(pcap_path):
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        console.print(f"[red][!] PCAP not found: {pcap_file}[/]")
        return

    console.print(f"\n[bold blue]* Analyzing DNS in:[/] {pcap_file.name}\n")

    # tshark command to get DNS transactions
    cmd = [
        "tshark", "-r", str(pcap_file),
        "-Y", "dns",
        "-T", "fields", "-E", "separator=,",
        "-e", "dns.id",
        "-e", "dns.flags.response",
        "-e", "dns.qry.name",
        "-e", "dns.flags.rcode"
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        console.print(f"[red][!] Failed to start tshark: {e}[/]")
        return

    # Track queries and responses
    queries = {}  # txid -> query name
    unanswered = defaultdict(int)
    rcode_counts = defaultdict(int)
    total_queries = total_responses = 0

    for line in proc.stdout:
        parts = line.strip().split(",")
        if len(parts) < 4:
            continue
        txid, is_response, name, rcode = parts
        if not txid:
            continue

        if is_response == '0':  # query
            total_queries += 1
            queries[txid] = name or "<no-name>"
        else:  # response
            total_responses += 1
            # count response codes
            rcode_counts[rcode or '0'] += 1
            # if we saw the query, remove it from unanswered
            if txid in queries:
                del queries[txid]
            else:
                # response w/o known query
                unanswered["<no-query-record>"] += 1

    proc.stdout.close()
    proc.wait()

    # Anything left in queries is unanswered
    for name in queries.values():
        unanswered[name] += 1

    # Summary
    console.print(f"Total DNS queries : {total_queries}")
    console.print(f"Total DNS responses: {total_responses}")
    console.print(f"Unanswered queries : {sum(unanswered.values())}\n")

    # Table: Response codes
    if rcode_counts:
        tbl = Table(title="DNS Response Codes", show_lines=True)
        tbl.add_column("RCode", style="cyan")
        tbl.add_column("Count", justify="right")
        for code, cnt in sorted(rcode_counts.items(), key=lambda kv: int(kv[0])):
            tbl.add_row(code, str(cnt))
        console.print(tbl)
    else:
        console.print("[green]No DNS responses found.[/green]")

    # Table: Top Unanswered Queries (show up to 10)
    if unanswered:
        tbl2 = Table(title="Top Unanswered Queries", show_lines=True)
        tbl2.add_column("Query Name", style="magenta")
        tbl2.add_column("Count", justify="right")
        for name, cnt in sorted(unanswered.items(), key=lambda kv: kv[1], reverse=True)[:10]:
            tbl2.add_row(name, str(cnt))
        console.print(tbl2)
    else:
        console.print("[green]All DNS queries got responses.[/green]")

    console.print(f"\n[bold green]* DNS analysis complete![/]\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("Usage: python3 pdiag08_dns_issues.py <path_to_pcap>")
    else:
        analyze(sys.argv[1])

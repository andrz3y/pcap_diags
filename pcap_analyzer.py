"""
PCAP ANALYZER 

NAME:       pcap_analyzer.py      

VERSION:    1.1.3

FUNCTIONALITY: 
- start with list of all .pcap and .pcapng files under ./pcaps/
- select a PCAP file by number
- shows a menu (display_menu()) of available analysis modules from under ./pdiags 
- runs selected module on a .pcap file 


RUN: 
source venv/bin/activate

python3 pcap_analyzer.py
- 


UPDATE: 1.1.2_continous_menu
- After running a module, returns to menu so user can pick another option or quit.

#UPDATE:1.1.3_back_to_file_selection
- Adds option 'b' to go back to PCAP selection
"""

# Python imports 
from pathlib import Path
import datetime
import sys
import os
from rich.console import Console
from rich.panel import Panel

# Module imports matching pdiags files (menu option = module number)
from pdiags import pdiag01_conversation_analyzer
from pdiags import pdiag02_endhost_general
from pdiags import pdiag03_endhost_geoip
from pdiags import pdiag04_badpackets
from pdiags import pdiag05_vsan_perf_checker
from pdiags import pdiag06_filetransfer
from pdiags import pdiag07_vpn
from pdiags import pdiag08_dns_issues 
from pdiags import pdiag09_read_everypcap

# Script version
__version__ = "1.1.3"

# Define paths
BASE_DIR = Path(__file__).parent.resolve()
PCAP_DIR = BASE_DIR / "pcaps"

### FUNCTIONS ### 

def print_header():
    script_name = Path(__file__).name
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("="*75)
    print(f"Script Name : {script_name}")
    print(f"Version     : {__version__}")
    print(f"Run Time    : {current_time}")
    print("="*75)

def list_pcaps():
    if not PCAP_DIR.exists() or not PCAP_DIR.is_dir():
        print(f"[!] PCAP directory '{PCAP_DIR}' does not exist.")
        return []
    files = list(PCAP_DIR.glob("*.pcap")) + list(PCAP_DIR.glob("*.pcapng"))
    return sorted(files)

console = Console()

def display_menu():
    menu_text = """
[bold cyan]1.[/] Conversation analyzer
[bold cyan]2.[/] End Host General
[bold cyan]3.[/] End Host GeoInfo

[bold cyan]4.[/] Check for Bad Packets
[bold cyan]5.[/] Check for vSAN performance issues

[bold cyan]6.[/] Check for File Transfer
[bold cyan]7.[/] Check for VPN packets
[bold cyan]8.[/] Check for DNS issues

[bold red]9.[/] [red]Read EVERY packet [/]

[bold yellow]b.[/] Back to PCAP selection
[bold green]c.[/] Clean Screen
[bold magenta]q.[/] Quit
    """
    console.print(
        Panel(
            menu_text,
            title="[bold white]Select analysis module:[/]",
            expand=False,
            border_style="blue"
        )
    )
    return input("\nEnter your choice (1-9, b, c or q): ").strip()

def handle_menu_choice(choice, pcap_file):
    print(f"\n[*] Selected menu option: {choice}")
    print(f"[*] PCAP file selected: {pcap_file}")
    if choice == "1":
        print("[*] Running Conversation Analyzer...\n")
        pdiag01_conversation_analyzer.analyze(pcap_file)
    elif choice == "2":
        print("[*] Running End Host General...\n")
        pdiag02_endhost_general.analyze(pcap_file)
    elif choice == "3":
        print("[*] Running End Host GeoInfo...\n")
        pdiag03_endhost_geoip.analyze(pcap_file)
    elif choice == "4":
        print("[*] Running Bad Packet Checker...\n")
        pdiag04_badpackets.analyze(pcap_file)
    elif choice == "5":
        print("[*] Running vSAN Performance Checker...\n")
        pdiag05_vsan_perf_checker.analyze(pcap_file)
    elif choice == "6":
        print("[*] Running File Transfer Checker...\n")
        pdiag06_filetransfer.analyze(pcap_file)
    elif choice == "7":
        print("[*] Running VPN Packet Checker...\n")
        pdiag07_vpn.analyze(pcap_file)
    elif choice == "8":
        print("[*] Running DNS Issues Checker...\n")
        pdiag08_dns_issues.analyze(pcap_file)
    elif choice == "9":
        print("[*] Running Read EVERY packet...\n")
        pdiag09_read_everypcap.analyze(pcap_file)
    else:
        print("[!] Invalid choice. Please pick a valid option.")

def main():
    print_header()

    while True:  # Top-level: allow reselecting PCAP
        pcaps = list_pcaps()
        if not pcaps:
            print("[!] No pcap files found in the directory:", PCAP_DIR)
            print("    (Please add .pcap or .pcapng files to the 'pcaps' folder.)")
            sys.exit(1)

        print("\n---------------------")
        print("Available pcap files:")
        print("---------------------")
        for idx, pcap in enumerate(pcaps, 1):
            print(f"{idx}. {pcap.name}")

        # select a pcap
        while True:
            try:
                selection = int(input(f"\nSelect a pcap file by number (1-{len(pcaps)}): ").strip())
                if 1 <= selection <= len(pcaps):
                    pcap_file = pcaps[selection - 1]
                    break
                else:
                    print(f"[!] Please enter a number between 1 and {len(pcaps)}.")
            except ValueError:
                print("[!] Invalid input. Please enter a number.")

        # module menu loop
        while True:
            choice = display_menu()
            if choice.lower() == 'q':
                print("[*] Exiting PCAP Analyzer. Goodbye!")
                sys.exit(0)
            if choice.lower() == 'b':                           # back to file selection
                print("[*] Returning to PCAP selection...\n")
                break  # breaks to outer loop
            handle_menu_choice(choice, pcap_file)
            if choice.lower() == 'c':                           # clean screen
                print("[*] Clean screen...\n")
                os.system('clear')
                break  # breaks to outer loop
            handle_menu_choice(choice, pcap_file)


if __name__ == "__main__":
    main()

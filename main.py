#!/usr/bin/env python3
# main.py
"""
██████╗ ██████╗ ██╗
██╔══██╗██╔══██╗██║
██║  ██║██████╔╝██║
██║  ██║██╔═══╝ ██║
██████╔╝██║     ██║
╚═════╝ ╚═╝     ╚═╝
Deep Packet Inspection Engine
Developed by Mohammed Waseem Siddique
"""
import argparse
from dpi_engine import DPIEngine
from config import INTERFACE, PCAP_FILE, OUTPUT_CSV

def banner():
    print(r"""
    ____  ___   ____    ____  _  _______   ____
   / __ \/   | / __ \  / __ \/ |/ / ___/  /  _/
  / /_/ / /| |/ /_/ / / /_/ /    / /__  _/ /  
 / ____/ ___ / ____/ / ____/ /|  / /_/  / /   
/_/   /_/  |_/_/     /_/   /_/ |_/_____/ /___/ 

    """)
    print("=" * 60)
    print("   Developed by: Mohammed Waseem Siddique")
    print("   Ready to invest my time into more projects")
    print("   and real-world impactful opportunities.")
    print("=" * 60)
    print()

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Deep Packet Inspection Tool")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("-r", "--pcap", help="PCAP file to analyze")
    parser.add_argument("-o", "--output", default=OUTPUT_CSV, help="Output CSV file")
    args = parser.parse_args()

    iface = args.interface or (None if args.pcap else INTERFACE)
    pcap = args.pcap or PCAP_FILE

    engine = DPIEngine(interface=iface, pcap_file=pcap, output_csv=args.output)
    try:
        engine.start()
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except PermissionError:
        print("ERROR: Root/Administrator privileges required to capture live packets.")
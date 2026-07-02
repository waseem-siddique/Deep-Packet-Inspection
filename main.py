#!/usr/bin/env python3
import argparse
import sys
import threading
from pathlib import Path

from dpi.engine import DPIEngine

BANNER = """
  ____  ____  ___
 |  _ \\|  _ \\|_ _|
 | | | | |_) || |
 | |_| |  __/ | |
 |____/|_|   |___|

  Deep Packet Inspection Engine v2.0
  Developed by Mohammed Waseem Siddique
"""


def main():
    parser = argparse.ArgumentParser(
        description="Deep Packet Inspection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dpi -i eth0                          Live capture on eth0
  dpi -r capture.pcap                  Analyze PCAP file
  dpi -i eth0 --dashboard              Live capture with web dashboard
  dpi -i eth0 --api                    Live capture with REST API
  dpi -i eth0 --dashboard --api        Both dashboard and API
  dpi -r capture.pcap -o report.csv    Save results to CSV
        """,
    )

    parser.add_argument("-i", "--interface", help="Network interface for live capture")
    parser.add_argument("-r", "--pcap", help="PCAP file for offline analysis")
    parser.add_argument("-o", "--output", default="dpi_report.csv", help="Output CSV file")
    parser.add_argument("--geoip-db", help="Path to GeoLite2-City.mmdb database")
    parser.add_argument("--rules", help="Path to custom YAML rules file")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=5000, help="Dashboard port")
    parser.add_argument("--api", action="store_true", help="Launch REST API server")
    parser.add_argument("--api-port", type=int, default=8000, help="API server port")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)
    if not args.interface and not args.pcap:
        print("Error: Specify either -i for live capture or -r for PCAP analysis.")
        sys.exit(1)

    engine = DPIEngine(
        interface=args.interface,
        pcap_file=args.pcap,
        output_csv=args.output,
        geoip_db=args.geoip_db,
        rules_file=args.rules,
    )

    if args.dashboard:
        from dpi.dashboard import DashboardApp
        dashboard = DashboardApp(engine, port=args.dashboard_port)

    if args.api:
        from dpi.api import APIServer
        api = APIServer(engine, port=args.api_port)

    engine_thread = threading.Thread(target=engine.start, daemon=True)
    engine_thread.start()

    if args.dashboard and args.api:
        api_thread = threading.Thread(target=api.run, daemon=True)
        api_thread.start()
        dashboard.run()
    elif args.dashboard:
        dashboard.run()
    elif args.api:
        api.run()
    else:
        try:
            engine_thread.join()
        except KeyboardInterrupt:
            print("\nStopping engine...")
            engine.stop()


if __name__ == "__main__":
    main()
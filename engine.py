import logging
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any

from scapy.all import sniff, rdpcap, IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

from .protocols import HTTPDetector, DNSDetector, TLSDetector, SSHDetector, FTPDetector
from .detection import SignatureMatcher, RuleEngine
from .geoip import GeoIPMapper
from .utils.logger import CSVLogger

logger = logging.getLogger("DPI")


class DPIEngine:
    """Core Deep Packet Inspection engine with live capture and analysis capabilities."""

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        output_csv: str = "dpi_report.csv",
        geoip_db: Optional[str] = None,
        rules_file: Optional[str] = None,
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.csv_logger = CSVLogger(output_csv)
        self.geoip = GeoIPMapper(geoip_db)
        self.signature_matcher = SignatureMatcher()
        self.rule_engine = RuleEngine(rules_file)
        self.matcher = SignatureMatcher()

        # Protocol detectors
        self.detectors = [
            HTTPDetector(),
            DNSDetector(),
            TLSDetector(),
            SSHDetector(),
            FTPDetector(),
        ]

        # Statistics
        self.stats = {
            "packets_processed": 0,
            "protocols": defaultdict(int),
            "threats": defaultdict(int),
            "severity_counts": defaultdict(int),
            "bytes_transferred": 0,
            "start_time": None,
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
            "alerts": [],
        }
        self._running = False
        self._lock = threading.Lock()

    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process a single packet through the inspection pipeline."""
        with self._lock:
            self.stats["packets_processed"] += 1

        src_ip = dst_ip = "???"
        src_port = dst_port = 0
        protocol_str = "OTHER"
        details = ""
        severity = "INFO"
        geoip_src = ""
        geoip_dst = ""

        # Extract IP info
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.stats["unique_src_ips"].add(src_ip)
            self.stats["unique_dst_ips"].add(dst_ip)
            self.stats["bytes_transferred"] += len(packet)

        # Extract port info
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Extract payload for signature matching
        payload = b""
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)

        # Protocol detection
        detected = None
        for detector in self.detectors:
            result = detector.detect(packet)
            if result:
                detected = result
                break

        if detected:
            protocol_str = detected["protocol"]
            details = detected["details"]
            self.stats["protocols"][protocol_str] += 1

        # Signature-based threat detection
        payload_str = payload.decode("utf-8", errors="ignore")
        threats = self.matcher.match(payload_str)

        if threats:
            for name, sev, desc in threats:
                self.stats["threats"][name] += 1
                self.stats["severity_counts"][sev] += 1
                self.stats["alerts"].append({
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "threat": name,
                    "severity": sev,
                    "description": desc,
                })
                self.csv_logger.log(
                    src_ip, dst_ip, src_port, dst_port,
                    protocol_str, f"Threat: {name} - {desc}", sev
                )
                if len(self.stats["alerts"]) > 1000:
                    self.stats["alerts"] = self.stats["alerts"][-500:]

        # Rule engine evaluation
        packet_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": str(src_port),
            "dst_port": str(dst_port),
            "protocol": protocol_str,
            "details": details,
            "payload": payload_str[:200],
        }
        rule_alerts = self.rule_engine.evaluate(packet_info)
        for alert in rule_alerts:
            self.stats["severity_counts"][alert["severity"]] += 1

        # Log normal packet if protocol detected
        if detected and not threats:
            self.csv_logger.log(
                src_ip, dst_ip, src_port, dst_port,
                protocol_str, details, severity
            )

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol_str,
            "details": details,
            "severity": severity,
            "geoip_src": geoip_src,
            "geoip_dst": geoip_dst,
        }

    def start(self, packet_callback=None):
        """Start packet capture or PCAP analysis."""
        self.stats["start_time"] = datetime.now()
        self._running = True
        logger.info(f"DPI Engine starting...")

        def handle_packet(packet):
            result = self.process_packet(packet)
            if packet_callback and result:
                packet_callback(result)

        if self.pcap_file:
            logger.info(f"Reading packets from {self.pcap_file}")
            packets = rdpcap(self.pcap_file)
            for pkt in packets:
                if not self._running:
                    break
                handle_packet(pkt)
        else:
            logger.info(f"Sniffing on interface {self.interface}... (Ctrl+C to stop)")
            sniff(
                iface=self.interface,
                prn=handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )

        self._running = False
        self.csv_logger.close()
        self.geoip.close()
        logger.info(f"Engine stopped. {self.stats['packets_processed']} packets processed.")

    def stop(self):
        """Stop the engine gracefully."""
        self._running = False

    def get_stats(self) -> Dict[str, Any]:
        """Get current engine statistics."""
        with self._lock:
            return {
                "packets_processed": self.stats["packets_processed"],
                "protocols": dict(self.stats["protocols"]),
                "threats": dict(self.stats["threats"]),
                "severity_counts": dict(self.stats["severity_counts"]),
                "bytes_transferred": self.stats["bytes_transferred"],
                "unique_src_ips": len(self.stats["unique_src_ips"]),
                "unique_dst_ips": len(self.stats["unique_dst_ips"]),
                "alerts": self.stats["alerts"][-50:],
                "uptime": str(datetime.now() - self.stats["start_time"]) if self.stats["start_time"] else "N/A",
                "running": self._running,
            }
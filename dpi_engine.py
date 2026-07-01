# dpi_engine.py
import logging
from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello  # not used directly, we do manual
from protocol_detectors import ProtocolDetector
from signature_matcher import SignatureMatcher
from logger import CSVLogger

logger = logging.getLogger("DPI")

class DPIEngine:
    def __init__(self, interface=None, pcap_file=None, output_csv="dpi_report.csv"):
        self.interface = interface
        self.pcap_file = pcap_file
        self.logger = CSVLogger(output_csv)
        self.detector = ProtocolDetector()
        self.matcher = SignatureMatcher()
        self.packet_count = 0

    def process_packet(self, packet):
        self.packet_count += 1
        src_ip = dst_ip = "???"
        protocol = "OTHER"
        details = ""
        severity = "INFO"

        # Extract IP info
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

        payload = b""
        if packet.haslayer("TCP"):
            payload = bytes(packet["TCP"].payload)
        elif packet.haslayer("UDP"):
            payload = bytes(packet["UDP"].payload)

        # --- Protocol detection ---
        http_info = self.detector.detect_http(packet)
        if http_info:
            protocol = "HTTP"
            if "method" in http_info:
                details = f"Request {http_info['method']} {http_info['host']}{http_info['uri']}"
            else:
                details = f"Response {http_info.get('status_code','')} {http_info.get('reason','')}"

        dns_info = self.detector.detect_dns(packet)
        if dns_info:
            protocol = "DNS"
            details = f"Query {dns_info['qname']}"

        tls_info = self.detector.detect_tls(packet)
        if tls_info:
            protocol = "TLS"
            details = f"SNI: {tls_info.get('sni','')}"

        ssh_info = self.detector.detect_ssh(packet)
        if ssh_info:
            protocol = "SSH"
            details = f"Banner: {ssh_info['banner']}"

        ftp_info = self.detector.detect_ftp(packet)
        if ftp_info:
            protocol = "FTP"
            details = ftp_info.get("ftp_cmd","")

        # --- Signature matching on payload ---
        payload_str = payload.decode(errors="ignore")
        threats = self.matcher.match(payload_str)
        if threats:
            for name, sev in threats:
                self.logger.log(src_ip, dst_ip, protocol, f"Threat: {name}", sev)
                if sev == "CRITICAL" or sev == "HIGH":
                    logger.warning(f"🚨 Threat detected: {name} from {src_ip} to {dst_ip}")

        # Log the clean packet details if any
        if details:
            self.logger.log(src_ip, dst_ip, protocol, details)
        else:
            # General packet summary
            if packet.haslayer("TCP"):
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
                self.logger.log(src_ip, dst_ip, f"TCP/{dport}", f"sport={sport} dport={dport}", "DEBUG")
            elif packet.haslayer("UDP"):
                sport = packet["UDP"].sport
                dport = packet["UDP"].dport
                self.logger.log(src_ip, dst_ip, f"UDP/{dport}", f"sport={sport} dport={dport}", "DEBUG")

    def start(self):
        if self.pcap_file:
            logger.info(f"Reading packets from {self.pcap_file}")
            packets = rdpcap(self.pcap_file)
            for pkt in packets:
                self.process_packet(pkt)
        else:
            logger.info(f"Sniffing on interface {self.interface} ... (Ctrl+C to stop)")
            sniff(iface=self.interface, prn=self.process_packet, store=False)

        self.logger.close()
        logger.info(f"Finished processing {self.packet_count} packets. Report saved.")
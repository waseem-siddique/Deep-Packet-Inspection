# protocol_detectors.py
import re
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

# Load HTTP layer for Scapy
from scapy.main import load_layer
load_layer("http")

class ProtocolDetector:
    @staticmethod
    def detect_http(packet):
        """Extract HTTP request/response details."""
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            return {
                "method": req.Method.decode() if req.Method else "UNKNOWN",
                "host": req.Host.decode() if req.Host else "",
                "uri": req.Path.decode() if req.Path else "",
                "user_agent": req.User_Agent.decode() if req.User_Agent else ""
            }
        if packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            return {
                "status_code": resp.Status_Code.decode() if resp.Status_Code else "",
                "reason": resp.Reason.decode() if resp.Reason else ""
            }
        return None

    @staticmethod
    def detect_dns(packet):
        """Extract DNS query names."""
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # query
                qname = dns.qd.qname.decode() if dns.qd else ""
                return {"qname": qname}
        return None

    @staticmethod
    def detect_tls(packet):
        """Try to extract TLS Server Name Indication (SNI)."""
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            payload = bytes(packet[TCP].payload)
            # Very basic TLS ClientHello detection
            if len(payload) > 5 and payload[0] == 0x16:  # handshake
                try:
                    # SNI extraction (simplified)
                    if payload[5] == 0x01:  # ClientHello
                        # find server_name extension
                        # This is a simplified parse; a full implementation would walk extensions
                        sni_match = re.search(rb'\x00\x00.{2}\x00.{2}([\w\.\-]+)', payload)
                        if sni_match:
                            sni = sni_match.group(1).decode(errors="ignore")
                            return {"sni": sni}
                except:
                    pass
        return None

    @staticmethod
    def detect_ssh(packet):
        """Detect SSH banner exchange."""
        if packet.haslayer(TCP) and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
            payload = bytes(packet[TCP].payload)
            if payload.startswith(b"SSH-"):
                banner = payload.split(b"\r\n")[0].decode(errors="ignore")
                return {"banner": banner}
        return None

    @staticmethod
    def detect_ftp(packet):
        """Simple FTP command/response detection."""
        if packet.haslayer(TCP) and packet[TCP].dport == 21:
            payload = bytes(packet[TCP].payload)
            text = payload.decode(errors="ignore")
            if any(cmd in text for cmd in ["USER", "PASS", "RETR", "STOR", "220", "331"]):
                return {"ftp_cmd": text.strip()}
        return None
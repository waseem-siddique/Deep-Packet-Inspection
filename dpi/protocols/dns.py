from scapy.layers.dns import DNS


class DNSDetector:
    """Detects and parses DNS queries."""

    @staticmethod
    def detect(packet):
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0 and dns.qd:
                qname = dns.qd.qname.decode() if dns.qd.qname else ""
                return {
                    "protocol": "DNS",
                    "details": f"Query {qname}"
                }
        return None
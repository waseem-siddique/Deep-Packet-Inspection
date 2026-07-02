from scapy.layers.inet import TCP


class SSHDetector:
    """Detects SSH traffic and extracts banner information."""

    @staticmethod
    def detect(packet):
        if not packet.haslayer(TCP):
            return None

        sport = packet[TCP].sport
        dport = packet[TCP].dport

        if sport != 22 and dport != 22:
            return None

        payload = bytes(packet[TCP].payload)
        if payload.startswith(b"SSH-"):
            banner = payload.split(b"\r\n")[0].decode(errors="ignore")
            return {
                "protocol": "SSH",
                "details": f"Banner: {banner}"
            }

        return {"protocol": "SSH", "details": "Connection established"}
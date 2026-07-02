from scapy.layers.inet import TCP


class FTPDetector:
    """Detects FTP commands and responses."""

    FTP_COMMANDS = ["USER", "PASS", "RETR", "STOR", "LIST", "QUIT",
                    "PORT", "PASV", "CWD", "DELE", "MKD", "RMD"]

    @staticmethod
    def detect(packet):
        if not packet.haslayer(TCP):
            return None

        dport = packet[TCP].dport
        if dport != 21:
            return None

        payload = bytes(packet[TCP].payload)
        if not payload:
            return None

        try:
            text = payload.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

        if not text:
            return None

        # Check for FTP commands
        for cmd in FTPDetector.FTP_COMMANDS:
            if text.upper().startswith(cmd):
                # Mask password
                if cmd == "PASS":
                    return {
                        "protocol": "FTP",
                        "details": f"Command: PASS ***"
                    }
                return {
                    "protocol": "FTP",
                    "details": f"Command: {text[:50]}"
                }

        # Check for FTP response codes
        if len(text) >= 3 and text[:3].isdigit():
            return {
                "protocol": "FTP",
                "details": f"Response: {text[:50]}"
            }

        return None
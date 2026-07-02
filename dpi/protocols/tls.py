from scapy.layers.inet import TCP


class TLSDetector:
    """Detects TLS traffic and extracts SNI from ClientHello."""

    @staticmethod
    def detect(packet):
        if not packet.haslayer(TCP):
            return None

        dport = packet[TCP].dport
        if dport != 443 and dport != 8443:
            return None

        payload = bytes(packet[TCP].payload)
        if len(payload) < 6:
            return None

        # Check for TLS ClientHello
        if payload[0] == 0x16 and payload[5] == 0x01:
            try:
                # Basic SNI extraction
                sni = TLSDetector._extract_sni(payload)
                if sni:
                    return {
                        "protocol": "TLS",
                        "details": f"SNI: {sni}"
                    }
            except Exception:
                pass

        return {"protocol": "TLS", "details": "Encrypted handshake"}

    @staticmethod
    def _extract_sni(payload):
        """Extract Server Name Indication from ClientHello."""
        try:
            # Skip record header (5 bytes) + handshake header (4 bytes)
            # + client version (2 bytes) + random (32 bytes)
            offset = 5 + 4 + 2 + 32

            # Skip session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            # Skip cipher suites
            cipher_len = int.from_bytes(payload[offset:offset+2], 'big')
            offset += 2 + cipher_len

            # Skip compression methods
            comp_len = payload[offset]
            offset += 1 + comp_len

            # Extensions
            if offset + 2 > len(payload):
                return None
            ext_len = int.from_bytes(payload[offset:offset+2], 'big')
            offset += 2
            end = offset + ext_len

            while offset < end:
                if offset + 4 > len(payload):
                    break
                ext_type = int.from_bytes(payload[offset:offset+2], 'big')
                ext_data_len = int.from_bytes(payload[offset+2:offset+4], 'big')
                offset += 4

                # SNI extension type is 0x0000
                if ext_type == 0x0000:
                    if offset + 5 > len(payload):
                        break
                    # Skip list length (2) + name type (1) + name length (2)
                    offset += 2
                    name_type = payload[offset]
                    offset += 1
                    name_len = int.from_bytes(payload[offset:offset+2], 'big')
                    offset += 2
                    sni = payload[offset:offset+name_len].decode('utf-8', errors='ignore')
                    return sni

                offset += ext_data_len

        except Exception:
            pass

        return None
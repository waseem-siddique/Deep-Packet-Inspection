from scapy.layers.http import HTTPRequest, HTTPResponse

class HTTPDetector:
    """Detects and parses HTTP traffic."""

    @staticmethod
    def detect(packet):
        result = {"protocol": None, "details": ""}

        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            method = req.Method.decode() if req.Method else "UNKNOWN"
            host = req.Host.decode() if req.Host else ""
            path = req.Path.decode() if req.Path else ""
            result["protocol"] = "HTTP"
            result["details"] = f"Request {method} {host}{path}"
            return result

        if packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            code = resp.Status_Code.decode() if resp.Status_Code else ""
            reason = resp.Reason.decode() if resp.Reason else ""
            result["protocol"] = "HTTP"
            result["details"] = f"Response {code} {reason}"
            return result

        return None
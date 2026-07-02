import pytest
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR

from dpi.protocols.http import HTTPDetector
from dpi.protocols.dns import DNSDetector
from dpi.protocols.ssh import SSHDetector
from dpi.protocols.ftp import FTPDetector


class TestHTTPDetector:
    def test_detect_http_get_request(self):
        packet = IP() / TCP(dport=80) / HTTPRequest(
            Method=b"GET",
            Host=b"example.com",
            Path=b"/index.html"
        )
        result = HTTPDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "HTTP"
        assert "GET" in result["details"]
        assert "example.com" in result["details"]

    def test_detect_http_response(self):
        packet = IP() / TCP(sport=80) / HTTPResponse(
            Status_Code=b"200",
            Reason=b"OK"
        )
        result = HTTPDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "HTTP"
        assert "200" in result["details"]

    def test_non_http_packet(self):
        packet = IP() / TCP(dport=80) / Raw(load=b"Not HTTP data")
        result = HTTPDetector.detect(packet)
        assert result is None


class TestDNSDetector:
    def test_detect_dns_query(self):
        packet = IP() / UDP(dport=53) / DNS(
            qr=0,
            qd=DNSQR(qname=b"google.com")
        )
        result = DNSDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "DNS"
        assert "google.com" in result["details"]

    def test_non_dns_packet(self):
        packet = IP() / UDP(dport=53) / Raw(load=b"Not DNS")
        result = DNSDetector.detect(packet)
        assert result is None


class TestSSHDetector:
    def test_detect_ssh_banner(self):
        packet = IP() / TCP(sport=22) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        result = SSHDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "SSH"
        assert "OpenSSH" in result["details"]

    def test_non_ssh_packet(self):
        packet = IP() / TCP(dport=22) / Raw(load=b"Not SSH")
        result = SSHDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "SSH"


class TestFTPDetector:
    def test_detect_ftp_user_command(self):
        packet = IP() / TCP(dport=21) / Raw(load=b"USER admin\r\n")
        result = FTPDetector.detect(packet)
        assert result is not None
        assert result["protocol"] == "FTP"
        assert "USER" in result["details"]

    def test_detect_ftp_pass_masked(self):
        packet = IP() / TCP(dport=21) / Raw(load=b"PASS secret123\r\n")
        result = FTPDetector.detect(packet)
        assert result is not None
        assert "***" in result["details"]

    def test_non_ftp_packet(self):
        packet = IP() / TCP(dport=80) / Raw(load=b"Not FTP")
        result = FTPDetector.detect(packet)
        assert result is None
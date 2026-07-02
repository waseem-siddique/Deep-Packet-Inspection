"""Protocol detection modules."""
from .http import HTTPDetector
from .dns import DNSDetector
from .tls import TLSDetector
from .ssh import SSHDetector
from .ftp import FTPDetector

__all__ = ["HTTPDetector", "DNSDetector", "TLSDetector", "SSHDetector", "FTPDetector"]
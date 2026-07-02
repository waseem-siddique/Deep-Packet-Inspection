import csv
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("DPI")


class CSVLogger:
    """Structured CSV logging for packet analysis results."""

    def __init__(self, filename="dpi_report.csv"):
        self.filename = Path(filename)
        self.file = open(self.filename, "w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        self.writer.writerow([
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "details", "severity", "geoip_src", "geoip_dst"
        ])
        self.count = 0

    def log(self, src_ip, dst_ip, src_port, dst_port, protocol, details,
            severity="INFO", geoip_src="", geoip_dst=""):
        timestamp = datetime.now().isoformat()
        self.writer.writerow([
            timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, details, severity, geoip_src, geoip_dst
        ])
        self.file.flush()
        self.count += 1
        if severity in ("CRITICAL", "HIGH"):
            logger.warning(f"THREAT [{severity}] {src_ip}:{src_port} -> "
                           f"{dst_ip}:{dst_port} [{protocol}] {details}")

    def get_stats(self):
        return {"total_packets": self.count}

    def close(self):
        self.file.close()
# logger.py
import csv
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger("DPI")

class CSVLogger:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, "w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        self.writer.writerow(["Timestamp", "Src IP", "Dst IP", "Protocol", "Details", "Severity"])

    def log(self, src_ip, dst_ip, protocol, details, severity="INFO"):
        timestamp = datetime.now().isoformat()
        self.writer.writerow([timestamp, src_ip, dst_ip, protocol, details, severity])
        self.file.flush()
        logger.info(f"{severity} | {src_ip} -> {dst_ip} [{protocol}] {details}")

    def close(self):
        self.file.close()
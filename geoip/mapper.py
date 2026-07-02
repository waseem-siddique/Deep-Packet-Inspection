import logging
from typing import Dict, Optional

logger = logging.getLogger("DPI")


class GeoIPMapper:
    """Maps IP addresses to geographic locations using MaxMind GeoLite2 database.
    
    To enable GeoIP, download the free GeoLite2 City database from:
    https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    
    Place the .mmdb file in the project root or set GEOIP_DB_PATH.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.reader = None
        self.enabled = False
        
        if db_path is None:
            from pathlib import Path
            possible_paths = [
                Path("GeoLite2-City.mmdb"),
                Path("geoip/GeoLite2-City.mmdb"),
                Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
            ]
            for path in possible_paths:
                if path.exists():
                    db_path = str(path)
                    break

        if db_path:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(db_path)
                self.enabled = True
                logger.info(f"GeoIP enabled with database: {db_path}")
            except ImportError:
                logger.warning("geoip2 not installed. Install with: pip install geoip2")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")
        else:
            logger.info("GeoIP database not found. GeoIP mapping disabled.")

    def lookup(self, ip: str) -> Dict[str, str]:
        """Look up geographic information for an IP address.
        
        Returns dict with country, city, latitude, longitude, or empty dict.
        """
        if not self.enabled or not self.reader:
            return {}

        # Skip private/local IPs
        if self._is_private(ip):
            return {"country": "Private Network", "city": "Local"}

        try:
            response = self.reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "latitude": str(response.location.latitude or ""),
                "longitude": str(response.location.longitude or ""),
            }
        except Exception:
            return {"country": "Unknown", "city": "Unknown"}

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if IP is in a private range."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
        except Exception:
            pass
        return False

    def close(self):
        if self.reader:
            self.reader.close()
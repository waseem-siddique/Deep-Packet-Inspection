import pytest
import json


class TestAPIServer:
    def test_api_server_import(self):
        from dpi.api.server import APIServer
        assert APIServer is not None

    def test_api_server_init(self):
        from dpi.api.server import APIServer
        from unittest.mock import Mock
        
        mock_engine = Mock()
        mock_engine._running = False
        server = APIServer(mock_engine, host="127.0.0.1", port=9999)
        
        assert server.host == "127.0.0.1"
        assert server.port == 9999
        assert server.app is not None

    def test_health_endpoint(self):
        from dpi.api.server import APIServer
        from unittest.mock import Mock
        
        mock_engine = Mock()
        mock_engine._running = True
        server = APIServer(mock_engine, host="127.0.0.1", port=9999)
        
        with server.app.test_client() as client:
            response = client.get("/health")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "healthy"

    def test_stats_endpoint(self):
        from dpi.api.server import APIServer
        from unittest.mock import Mock
        
        mock_engine = Mock()
        mock_engine._running = False
        mock_engine.get_stats.return_value = {
            "packets_processed": 100,
            "protocols": {"HTTP": 50, "DNS": 30},
        }
        server = APIServer(mock_engine, host="127.0.0.1", port=9999)
        
        with server.app.test_client() as client:
            response = client.get("/api/v1/stats")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["packets_processed"] == 100

    def test_alerts_with_severity_filter(self):
        from dpi.api.server import APIServer
        from unittest.mock import Mock
        
        mock_engine = Mock()
        mock_engine._running = False
        mock_engine.get_stats.return_value = {
            "alerts": [
                {"threat": "SQL Injection", "severity": "CRITICAL"},
                {"threat": "Suspicious UA", "severity": "LOW"},
            ]
        }
        server = APIServer(mock_engine, host="127.0.0.1", port=9999)
        
        with server.app.test_client() as client:
            response = client.get("/api/v1/alerts?severity=CRITICAL")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data) == 1
            assert data[0]["severity"] == "CRITICAL"

    def test_export_csv(self):
        from dpi.api.server import APIServer
        from unittest.mock import Mock
        
        mock_engine = Mock()
        mock_engine._running = False
        mock_engine.get_stats.return_value = {
            "packets_processed": 50,
            "protocols": {"HTTP": 30},
            "threats": {},
            "unique_src_ips": 5,
            "unique_dst_ips": 3,
            "bytes_transferred": 1024,
            "uptime": "0:05:00",
        }
        server = APIServer(mock_engine, host="127.0.0.1", port=9999)
        
        with server.app.test_client() as client:
            response = client.get("/api/v1/export/csv")
            assert response.status_code == 200
            assert "text/csv" in response.content_type
import json
import csv
import io
from datetime import datetime
from flask import Flask, jsonify, request, send_file, Response


class APIServer:
    """REST API for interacting with the DPI engine."""

    def __init__(self, engine, host="0.0.0.0", port=8000):
        self.engine = engine
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/health")
        def health():
            return jsonify({
                "status": "healthy",
                "engine": "running" if self.engine._running else "stopped",
                "timestamp": datetime.now().isoformat(),
            })

        @self.app.route("/api/v1/stats")
        def stats():
            return jsonify(self.engine.get_stats())

        @self.app.route("/api/v1/protocols")
        def protocols():
            stats = self.engine.get_stats()
            return jsonify(stats.get("protocols", {}))

        @self.app.route("/api/v1/threats")
        def threats():
            stats = self.engine.get_stats()
            return jsonify({
                "threats": stats.get("threats", {}),
                "severity_counts": stats.get("severity_counts", {}),
                "recent_alerts": stats.get("alerts", [])[-20:],
            })

        @self.app.route("/api/v1/alerts")
        def alerts():
            stats = self.engine.get_stats()
            severity = request.args.get("severity")
            alerts_list = stats.get("alerts", [])
            if severity:
                alerts_list = [a for a in alerts_list if a.get("severity") == severity.upper()]
            limit = request.args.get("limit", 50, type=int)
            return jsonify(alerts_list[-limit:])

        @self.app.route("/api/v1/rules", methods=["GET", "POST"])
        def rules():
            if request.method == "GET":
                return jsonify(self.engine.rule_engine.to_dict())
            elif request.method == "POST":
                data = request.get_json()
                if data and "rules" in data:
                    self.engine.rule_engine.rules = data["rules"]
                    return jsonify({"status": "updated", "count": len(data["rules"])})
                return jsonify({"error": "Invalid format"}), 400

        @self.app.route("/api/v1/signatures", methods=["GET", "POST"])
        def signatures():
            if request.method == "GET":
                sigs = [
                    {"name": s.name, "severity": s.severity, "description": s.description}
                    for s in self.engine.signature_matcher.signatures
                ]
                return jsonify(sigs)
            elif request.method == "POST":
                data = request.get_json()
                if data and all(k in data for k in ["name", "pattern", "severity"]):
                    self.engine.signature_matcher.add_signature(
                        data["name"],
                        data["pattern"],
                        data["severity"],
                        data.get("description", ""),
                    )
                    return jsonify({"status": "added"})
                return jsonify({"error": "Missing required fields"}), 400

        @self.app.route("/api/v1/export/csv")
        def export_csv():
            stats = self.engine.get_stats()
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Packets Processed", stats.get("packets_processed", 0)])
            writer.writerow(["Unique Source IPs", stats.get("unique_src_ips", 0)])
            writer.writerow(["Unique Dest IPs", stats.get("unique_dst_ips", 0)])
            writer.writerow(["Bytes Transferred", stats.get("bytes_transferred", 0)])
            writer.writerow(["Uptime", stats.get("uptime", "N/A")])
            writer.writerow([])
            writer.writerow(["Protocol", "Count"])
            for proto, count in stats.get("protocols", {}).items():
                writer.writerow([proto, count])
            writer.writerow([])
            writer.writerow(["Threat", "Count"])
            for threat, count in stats.get("threats", {}).items():
                writer.writerow([threat, count])
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment;filename=dpi_export.csv"},
            )

        @self.app.route("/api/v1/export/json")
        def export_json():
            stats = self.engine.get_stats()
            return jsonify(stats)

    def run(self, debug=False):
        """Start the REST API server."""
        from waitress import serve
        print(f"API server running on http://{self.host}:{self.port}")
        print(f"Health check: http://{self.host}:{self.port}/health")
        print(f"API docs: http://{self.host}:{self.port}/api/v1/")
        serve(self.app, host=self.host, port=self.port)
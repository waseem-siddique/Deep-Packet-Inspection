import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import threading


class DashboardApp:
    """Web-based dashboard for real-time packet monitoring."""

    def __init__(self, engine, host="0.0.0.0", port=5000):
        self.engine = engine
        self.host = host
        self.port = port
        self.app = Flask(__name__, template_folder="templates")
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self._setup_routes()
        self._thread = None

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template("dashboard.html")

        @self.app.route("/api/stats")
        def stats():
            return jsonify(self.engine.get_stats())

        @self.app.route("/api/alerts")
        def alerts():
            stats = self.engine.get_stats()
            return jsonify(stats.get("alerts", []))

        @self.app.route("/api/start", methods=["POST"])
        def start_engine():
            if not self.engine._running:
                self._thread = threading.Thread(
                    target=self.engine.start,
                    kwargs={"packet_callback": self._on_packet},
                    daemon=True,
                )
                self._thread.start()
                return jsonify({"status": "started"})
            return jsonify({"status": "already_running"})

        @self.app.route("/api/stop", methods=["POST"])
        def stop_engine():
            self.engine.stop()
            return jsonify({"status": "stopped"})

    def _on_packet(self, packet_info):
        """Emit packet data to connected clients via WebSocket."""
        self.socketio.emit("packet", packet_info)

    def start_broadcast(self):
        """Start broadcasting stats to clients periodically."""
        def broadcast_loop():
            import time
            while self.engine._running:
                time.sleep(1)
                self.socketio.emit("stats", self.engine.get_stats())

        thread = threading.Thread(target=broadcast_loop, daemon=True)
        thread.start()

    def run(self, debug=False):
        """Start the dashboard server."""
        if self.engine._running:
            self.start_broadcast()
        self.socketio.run(self.app, host=self.host, port=self.port, debug=debug)
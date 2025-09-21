import json
import os
import random
import threading
import time
from datetime import datetime
from typing import Any, Dict

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

LOG_PATH = os.path.abspath(
    os.environ.get("DEMO_APP_LOG", os.path.join(os.path.dirname(__file__), "logs", "demo-app.log"))
)
IDS_PROXY_INGEST = os.environ.get("IDS_PROXY_INGEST", "http://localhost:8000/ingest")
FORWARD_TIMEOUT = float(os.environ.get("IDS_PROXY_TIMEOUT", "2"))
FORWARD_RETRIES = int(os.environ.get("IDS_PROXY_RETRIES", "2"))
FORWARD_BACKOFF_BASE = float(os.environ.get("IDS_PROXY_RETRY_BACKOFF", "0.3"))
FORWARD_BACKOFF_JITTER = float(os.environ.get("IDS_PROXY_RETRY_JITTER", "0.2"))

_log_lock = threading.Lock()


def _write_log_line(event: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    line = json.dumps(event, sort_keys=True)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _forward_to_ids_proxy(event: Dict[str, Any]) -> None:
    attempts = max(0, FORWARD_RETRIES) + 1
    for attempt in range(attempts):
        try:
            requests.post(IDS_PROXY_INGEST, json=event, timeout=FORWARD_TIMEOUT)
            return
        except requests.RequestException:
            if attempt == attempts - 1:
                # We intentionally swallow the error – the IDS proxy might not be running
                # when developing locally. The log file still retains every event.
                return
            backoff = FORWARD_BACKOFF_BASE * (2 ** attempt)
            jitter = random.uniform(0, FORWARD_BACKOFF_JITTER)
            time.sleep(backoff + jitter)


def _guess_source_ip() -> str:
    """Allow tests/attack-sim to spoof the origin so we can demo multiple attackers."""
    header = request.headers.get("X-Forwarded-For")
    if header:
        return header.split(",")[0].strip()
    override = request.args.get("__source_ip")
    if override:
        return override
    return request.remote_addr or "unknown"


def _make_event(event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
    base_event = {
        "app": "demo-app",
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event_type": event_type,
        "source_ip": _guess_source_ip(),
        "path": request.path,
        "method": request.method,
    }
    base_event.update(details)
    return base_event


@app.route("/", methods=["GET"])
def index() -> Any:
    message = {
        "message": "Simple IDS demo app is running.",
        "endpoints": {
            "POST /login": "Submit {username, password}. Correct password is 'password123'.",
            "GET /search?q=term": "Simulates a database search endpoint.",
            "GET /probe/<port>": "Used by the attack simulator to mimic port scans.",
        },
    }
    return jsonify(message)


@app.route("/login", methods=["POST"])
def login() -> Any:
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")
    success = username == "admin" and password == "password123"

    event = _make_event(
        "login_attempt",
        {
            "username": username,
            "success": success,
        },
    )
    _write_log_line(event)
    _forward_to_ids_proxy(event)

    status = "success" if success else "failure"
    message = "Login {}".format("succeeded" if success else "failed")
    return jsonify({"status": status, "message": message})


@app.route("/search", methods=["GET"])
def search() -> Any:
    query = request.args.get("q", "")

    event = _make_event(
        "search",
        {
            "query": query,
        },
    )
    _write_log_line(event)
    _forward_to_ids_proxy(event)

    return jsonify(
        {
            "results": [
                {
                    "title": "Demo result",
                    "description": "This is a placeholder search response.",
                }
            ],
            "query": query,
        }
    )


@app.route("/probe/<int:port>", methods=["GET"])
def probe(port: int) -> Any:
    event = _make_event(
        "port_probe",
        {
            "port": port,
        },
    )
    _write_log_line(event)
    _forward_to_ids_proxy(event)

    return jsonify(
        {
            "message": "Port probe recorded",
            "port": port,
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

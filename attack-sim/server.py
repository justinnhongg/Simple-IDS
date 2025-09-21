import os
import threading
import time
from typing import Any, Dict, List

import requests
from flask import Flask, jsonify, request

from run_attacks import run_scenarios

DEFAULT_TARGET = os.environ.get("ATTACK_SIM_TARGET", "http://demo-app:5000")
TARGET_HEALTH_PATH = os.environ.get("ATTACK_SIM_TARGET_HEALTH", "/")
DEFAULT_SCENARIOS = ["bruteforce", "sql", "portscan"]

app = Flask(__name__)

_run_lock = threading.Lock()
_is_running = False
_run_history: List[Dict[str, Any]] = []


def _record_run_entry(entry: Dict[str, Any]) -> None:
    with _run_lock:
        _run_history.append(entry)
        if len(_run_history) > 25:
            del _run_history[:-25]


def _set_running(value: bool) -> None:
    global _is_running
    with _run_lock:
        _is_running = value


def _wait_for_target(url: str, timeout_seconds: int = 60) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=3)
            if response.ok:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


def _get_running() -> bool:
    with _run_lock:
        return _is_running


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "running": _get_running()})


@app.get("/runs")
def runs() -> Any:
    with _run_lock:
        history = list(reversed(_run_history))
    return jsonify({"runs": history})


@app.post("/run")
def trigger_run() -> Any:
    if _get_running():
        return jsonify({"status": "busy", "message": "Attack simulator is already running"}), 409

    payload = request.get_json(silent=True) or {}
    scenarios = payload.get("scenarios") or ([] if payload.get("all") is False else DEFAULT_SCENARIOS)
    if not scenarios:
        scenarios = DEFAULT_SCENARIOS if payload.get("all", True) else DEFAULT_SCENARIOS
    pace = float(payload.get("pace", 1.0))
    target = payload.get("target", DEFAULT_TARGET)
    health_path = payload.get("health_path", TARGET_HEALTH_PATH)

    request_meta = {
        "requested_scenarios": scenarios,
        "pace": pace,
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    def _worker() -> None:
        start = time.perf_counter()
        _set_running(True)
        executed: List[str] = []
        status = "completed"
        error_message = None
        try:
            health_url = target.rstrip('/') + health_path
            if not _wait_for_target(health_url):
                raise RuntimeError(f"Target {target} did not become available")
            executed = run_scenarios(target, scenarios, pace)
        except Exception as exc:  # noqa: BLE001
            status = "error"
            error_message = str(exc)
        finally:
            duration = time.perf_counter() - start
            entry = {
                **request_meta,
                "status": status,
                "health_path": health_path,
                "executed": executed,
                "duration_seconds": round(duration, 2),
            }
            if error_message:
                entry["error"] = error_message
            _record_run_entry(entry)
            _set_running(False)

    thread = threading.Thread(target=_worker, name="attack-sim-run", daemon=True)
    thread.start()

    return jsonify({"status": "started", **request_meta})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))

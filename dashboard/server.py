import os
from typing import Any, Dict

import requests
from flask import Flask, Response, jsonify, make_response, render_template, request, stream_with_context

IDS_PROXY_EVENTS_URL = os.environ.get("IDS_PROXY_EVENTS_URL", "http://localhost:8000/events")
IDS_PROXY_TOP_URL = os.environ.get("IDS_PROXY_TOP_URL", "http://localhost:8000/top")
IDS_PROXY_METRICS_URL = os.environ.get("IDS_PROXY_METRICS_URL", "http://localhost:8000/metrics")
IDS_PROXY_EVENTS_STREAM_URL = os.environ.get("IDS_PROXY_EVENTS_STREAM_URL", "http://localhost:8000/events/stream")
IDS_PROXY_MUTE_URL = os.environ.get("IDS_PROXY_MUTE_URL", "http://localhost:8000/mute")
IDS_PROXY_EXPORT_URL = os.environ.get("IDS_PROXY_EXPORT_URL", "http://localhost:8000/export")
REFRESH_SECONDS = int(os.environ.get("DASHBOARD_REFRESH", "5"))
IDS_PROXY_CONTEXT_URL = os.environ.get("IDS_PROXY_CONTEXT_URL", "http://localhost:8000/context")
ATTACK_SIM_URL = os.environ.get("ATTACK_SIM_URL", "http://localhost:9000")
API_TIMEOUT = float(os.environ.get("DASHBOARD_API_TIMEOUT", "5"))

app = Flask(__name__)


@app.route("/")
def index() -> Any:
    return render_template("index.html", refresh_seconds=REFRESH_SECONDS)


@app.route("/history")
def history() -> Any:
    events: list[Dict[str, Any]] = []
    error: str | None = None
    try:
        response = requests.get(IDS_PROXY_EVENTS_URL, timeout=API_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        raw_events = payload.get("events", payload)
        if isinstance(raw_events, list):
            events = sorted(
                raw_events,
                key=lambda item: item.get("timestamp", ""),
                reverse=True,
            )
    except requests.RequestException as exc:
        error = str(exc)
    return render_template("history.html", events=events, error=error)


@app.route("/api/events")
def api_events() -> Any:
    try:
        response = requests.get(IDS_PROXY_EVENTS_URL, timeout=API_TIMEOUT)
        response.raise_for_status()
        payload: Dict[str, Any] = response.json()
        events = payload.get("events", payload)
        return jsonify({"events": events})
    except requests.RequestException as exc:
        return jsonify({"events": [], "error": str(exc)}), 502


@app.route("/api/top")
def api_top() -> Any:
    try:
        response = requests.get(IDS_PROXY_TOP_URL, timeout=API_TIMEOUT)
        response.raise_for_status()
        payload: Dict[str, Any] = response.json()
        top = payload.get("top", [])
        return jsonify({"top": top})
    except requests.RequestException as exc:
        return jsonify({"top": [], "error": str(exc)}), 502


@app.route("/api/context/<path:ip>")
def api_context(ip: str) -> Any:
    try:
        response = requests.get(f"{IDS_PROXY_CONTEXT_URL}/{ip}", timeout=API_TIMEOUT)
        response.raise_for_status()
        payload: Dict[str, Any] = response.json()
        return jsonify(payload)
    except requests.RequestException as exc:
        return jsonify({"ip": ip, "events": [], "error": str(exc)}), 502


@app.route("/api/metrics")
def api_metrics() -> Any:
    try:
        response = requests.get(IDS_PROXY_METRICS_URL, timeout=API_TIMEOUT)
        response.raise_for_status()
        payload: Dict[str, Any] = response.json()
        return jsonify(payload)
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/api/events/stream")
def api_events_stream() -> Response:
    def generate() -> Any:
        try:
            with requests.get(IDS_PROXY_EVENTS_STREAM_URL, stream=True, timeout=(API_TIMEOUT, 60)) as upstream:
                upstream.raise_for_status()
                for line in upstream.iter_lines(decode_unicode=True):
                    if line is None:
                        continue
                    yield f"{line}\n"
        except requests.RequestException as exc:
            yield f"event: error\ndata: {exc}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.route("/api/attack", methods=["POST"])
def api_attack() -> Any:
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    try:
        response = requests.post(f"{ATTACK_SIM_URL}/run", json=payload, timeout=API_TIMEOUT)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        status = getattr(exc.response, "status_code", 502)
        message = str(exc)
        try:
            data = exc.response.json() if exc.response is not None else {}
            message = data.get("message", message)
        except Exception:
            pass
        return jsonify({"status": "error", "message": message}), status


@app.route("/api/attack/status")
def api_attack_status() -> Any:
    try:
        health_resp = requests.get(f"{ATTACK_SIM_URL}/health", timeout=API_TIMEOUT)
        health_resp.raise_for_status()
        runs_resp = requests.get(f"{ATTACK_SIM_URL}/runs", timeout=API_TIMEOUT)
        runs_resp.raise_for_status()
        return jsonify({
            "health": health_resp.json(),
            "runs": runs_resp.json().get("runs", []),
        })
    except requests.RequestException as exc:
        return jsonify({"status": "error", "message": str(exc)}), 502


@app.route("/api/mute", methods=["POST"])
def api_mute() -> Any:
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    try:
        response = requests.post(IDS_PROXY_MUTE_URL, json=payload, timeout=API_TIMEOUT)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        status = getattr(exc.response, "status_code", 502)
        message = str(exc)
        try:
            data = exc.response.json() if exc.response is not None else {}
            message = data.get("message", message)
        except Exception:
            pass
        return jsonify({"status": "error", "message": message}), status


@app.route("/api/export/<path:alert_id>")
def api_export(alert_id: str) -> Response:
    try:
        upstream = requests.get(f"{IDS_PROXY_EXPORT_URL}/{alert_id}", timeout=API_TIMEOUT)
        upstream.raise_for_status()
        response = make_response(upstream.content)
        response.headers["Content-Type"] = upstream.headers.get("Content-Type", "application/json")
        disposition = upstream.headers.get("Content-Disposition")
        if not disposition:
            response.headers["Content-Disposition"] = f"attachment; filename={alert_id}.json"
        return response
    except requests.RequestException as exc:
        status = getattr(exc.response, "status_code", 502)
        message = str(exc)
        return jsonify({"status": "error", "message": message}), status


@app.route("/health", methods=["GET"])
def health() -> Any:
    metrics_payload: Dict[str, Any] = {}
    error: str | None = None
    try:
        response = requests.get(IDS_PROXY_METRICS_URL, timeout=API_TIMEOUT)
        response.raise_for_status()
        metrics_payload = response.json()
    except requests.RequestException as exc:
        error = str(exc)
    return render_template(
        "health.html",
        metrics=metrics_payload,
        error=error,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3000"))
    app.run(host="0.0.0.0", port=port)

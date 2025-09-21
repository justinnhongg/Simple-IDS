from __future__ import annotations

import os
from typing import Any, Dict

try:
    import requests
except ImportError:  # pragma: no cover - fallback for lightweight environments
    requests = None  # type: ignore

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:3000")


def build_payload(alert: Dict[str, Any]) -> Dict[str, Any]:
    explanation = alert.get("explanation") or alert.get("summary") or "Suspicious activity detected."
    remediation = alert.get("remediation") or "Review the incident in the dashboard."
    severity = (alert.get("severity") or "medium").lower()
    color = "danger" if severity == "high" else "warning"

    attachment: Dict[str, Any] = {
        "fallback": remediation,
        "color": color,
        "fields": [
            {"title": "Endpoint", "value": alert.get("target") or "-", "short": True},
            {"title": "Source", "value": alert.get("source_ip") or "-", "short": True},
            {"title": "Remediation", "value": remediation, "short": False},
        ],
        "actions": [
            {"type": "button", "text": "Open Dashboard", "url": DASHBOARD_URL},
        ],
    }

    return {
        "text": f":rotating_light: *{alert.get('title') or alert.get('type', 'Alert')}*",
        "attachments": [attachment],
    }


def notify(alert: Dict[str, Any]) -> bool:
    """Send alert to Slack if webhook configured. Returns True on success."""
    if not SLACK_WEBHOOK_URL:
        return False
    if requests is None:
        return False
    payload = build_payload(alert)
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False

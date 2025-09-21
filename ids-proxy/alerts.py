from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict

ALERT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "brute_force": {
        "title": "Brute force login attempts",
        "explanation": (
            "Detected {count} failed logins for username `{username}` from {ip} in the last {window}s. "
            "Likely credential stuffing/brute-force."
        ),
        "remediation": (
            "Rate-limit login attempts, enforce account lockout after {threshold} failed tries, and consider "
            "CAPTCHA or MFA for sensitive endpoints."
        ),
    },
    "sql_injection": {
        "title": "SQL injection attempt",
        "explanation": (
            "Request contained SQL-like payload `{payload}` on {path}. If successful, this could expose "
            "database rows or enable data exfiltration."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements. Example: "
            "`db.query('SELECT * FROM items WHERE name = ?', [name])`."
        ),
    },
    "port_scan": {
        "title": "Port scanning behavior",
        "explanation": (
            "Observed probes to {ports} distinct ports from {ip} in {window}s. This is reconnaissance activity."
        ),
        "remediation": (
            "Block the IP temporarily or rate-limit unusual connection patterns; ensure internal services aren't publicly exposed."
        ),
    },
}


def build_alert(alert_type: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    template = ALERT_TEMPLATES.get(alert_type, {})
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    explanation = template.get("explanation", "").format(**meta)
    remediation = template.get("remediation", "").format(**meta)
    title = template.get("title", alert_type.replace("_", " ").title())

    alert_id = f"alert_{uuid.uuid4().hex[:12]}"
    severity = meta.get("severity", "medium")
    source_ip = meta.get("ip") or meta.get("source_ip")
    target = meta.get("path") or meta.get("target")

    summary = meta.get("summary") or explanation
    details = meta.get("details") or {}

    alert: Dict[str, Any] = {
        "id": alert_id,
        "timestamp": now,
        "type": alert_type,
        "title": title,
        "severity": severity,
        "source_ip": source_ip,
        "target": target,
        "explanation": explanation,
        "remediation": remediation,
        "summary": summary,
        "details": details,
        "meta": {k: v for k, v in meta.items() if k not in {"summary", "details"}},
    }

    return alert

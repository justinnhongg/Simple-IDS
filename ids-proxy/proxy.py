"""Simple IDS proxy service.

This module receives JSON events from the demo app, evaluates detection
rules, persists alerts, and fans them out to the dashboard and Slack.
"""

from __future__ import annotations

# Core Python utilities used across the detection pipeline.
import hashlib
import itertools
import json
import os
import queue
import threading
import time
from collections import defaultdict, deque  # handy containers for counters and context
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Set, Tuple

# Flask exposes HTTP endpoints; CORS lets the dashboard poll from the browser; 
# allows my dashboarweb page to make requests to flask api on localhost:8000
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS

# Local helper modules keep alert formatting, persistence, and Slack delivery tidy.
from alerts import build_alert
from storage import append_event
from slack import notify as slack_notify

# Paths, limits, and tunable knobs mostly sourced from environment variables so
# the demo can be customised without touching code.
LOG_PATH = os.path.abspath(
    os.environ.get("IDS_PROXY_LOG", os.path.join(os.path.dirname(__file__), "logs", "ids-proxy.log"))
)
EVENT_STORE_PATH = os.path.abspath(
    os.environ.get("IDS_PROXY_EVENTS", os.path.join(os.path.dirname(__file__), "data", "events.json"))
)
MAX_EVENTS = int(os.environ.get("IDS_PROXY_MAX_EVENTS", "1000"))
CONTEXT_MAX = int(os.environ.get("IDS_PROXY_CONTEXT_MAX", "50"))

# Detection thresholds: tweak these values to make the demo fire quicker or slower
BRUTEFORCE_WINDOW_SECONDS = int(os.environ.get("IDS_PROXY_BRUTEFORCE_WINDOW_SECONDS", str(60)))
BRUTEFORCE_THRESHOLD = int(os.environ.get("IDS_PROXY_BRUTEFORCE_THRESHOLD", str(5)))
PORTSCAN_WINDOW_SECONDS = int(os.environ.get("IDS_PROXY_PORTSCAN_WINDOW_SECONDS", str(60)))
PORTSCAN_THRESHOLD = int(os.environ.get("IDS_PROXY_PORTSCAN_THRESHOLD", str(10)))

# Log rotation and mute defaults keep the proxy resilient during long demos.
LOG_MAX_BYTES = int(os.environ.get("IDS_PROXY_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
LOG_BACKUPS = int(os.environ.get("IDS_PROXY_LOG_BACKUPS", "1"))
MAINTENANCE_INTERVAL_SECONDS = int(os.environ.get("IDS_PROXY_MAINTENANCE_INTERVAL", "30"))
MUTE_DEFAULT_SECONDS = int(os.environ.get("IDS_PROXY_MUTE_DEFAULT_SECONDS", "300"))

# Allowlist of service ports we intentionally ignore (e.g. 80/443) so
# background health checks do not look like a hostile port scan.
_portscan_ignore_env = os.environ.get("PORTSCAN_IGNORE", "")
PORTSCAN_IGNORE_PORTS = {
    int(port.strip())
    for port in _portscan_ignore_env.split(",")
    if port.strip().isdigit()
}

# Simple signatures that catch obvious SQL injection attempts.
DEFAULT_SQLI_PATTERNS = [
    "' or",
    " or 1=1",
    "union select",
    "--",
    ";--",
    "drop table",
    "xp_",
    "sleep(",
    "benchmark(",
    "; "
]

_extra_patterns = [p.strip().lower() for p in os.environ.get("IDS_PROXY_SQLI_PATTERNS_EXTRA", "").split(",") if p.strip()]
SQLI_PATTERNS = DEFAULT_SQLI_PATTERNS + _extra_patterns

app = Flask(__name__)
CORS(app)  # let the dashboard running on a different port call our API

_os_lock = threading.Lock()


class TimeDedupe:
    """A simple TTL-based deduper: map keys to expiry timestamps.

    This avoids permanent suppression of alerts and keeps memory usage bounded
    for demo usage. Not optimized for extremely high cardinality, but fine
    for hackathon traffic volumes.
    """

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl = ttl_seconds
        self._store: Dict[str, datetime] = {}

    def add(self, key: str) -> None:
        self._store[key] = datetime.utcnow() + timedelta(seconds=self.ttl)

    def __contains__(self, key: str) -> bool:
        exp = self._store.get(key)
        if not exp:
            return False
        if exp < datetime.utcnow():
            # expired — remove and return False
            try:
                del self._store[key]
            except KeyError:
                pass
            return False
        return True


class ContentScanner:
    """Content scanner that prefers Aho-Corasick (pyahocorasick) and falls back to naive substring matching.

    Usage: scanner = ContentScanner(list_of_patterns); scanner.match(text) -> bool
    """

    def __init__(self, patterns: List[str]):
        self.patterns = [p.lower() for p in patterns]
        self.ahocorasick = None
        try:
            import ahocorasick as _ahocorasick  # type: ignore

            A = _ahocorasick.Automaton()
            for i, pat in enumerate(self.patterns):
                A.add_word(pat, (i, pat))
            A.make_automaton()
            self.ahocorasick = A
        except Exception:
            # pyahocorasick not available or failed; fallback to substring checks
            self.ahocorasick = None

    def match(self, text: str) -> bool:
        if not text:
            return False
        txt = text.lower()
        if self.ahocorasick:
            for _ in self.ahocorasick.iter(txt):
                return True
            return False
        # fallback
        return any(pat in txt for pat in self.patterns)


class CountMinSketch:
    """
        Small Count-Min Sketch for approximate counts (demo use).
        hashes each ip into a small tables and bumps counts
        to estimate "heavy hitter" IPs without storing every single one.
    """

    def __init__(self, width: int = 256, depth: int = 4) -> None:
        self.width = width
        self.depth = depth
        self.tables = [[0] * width for _ in range(depth)]

    def _hashes(self, key: str) -> List[int]:
        key_bytes = key.encode("utf-8", "ignore")
        out: List[int] = []
        for i in range(self.depth):
            digest = hashlib.blake2b(key_bytes + i.to_bytes(2, "little"), digest_size=8).digest()
            out.append(int.from_bytes(digest, "big") % self.width)
        return out

    def add(self, key: str, count: int = 1) -> None:
        for d, idx in enumerate(self._hashes(key)):
            self.tables[d][idx] += count

    def estimate(self, key: str) -> int:
        return min(self.tables[d][idx] for d, idx in enumerate(self._hashes(key)))


import heapq


class TopK:
    """Maintain an approximate Top-K list pairing Count-Min estimates (tiny fixed-sized data struct but are upper bounds) 
    with a min-heap cache. keep track of the k highest-count keys seen so far without storing exact counts. 
    """

    def __init__(self, k: int = 10) -> None:
        self.k = k
        self.heap: List[tuple[int, str]] = []  # (count, key)
        self.entries: Dict[str, int] = {}

    def maybe_add(self, key: str, count: int) -> None:
        prev = self.entries.get(key)
        if prev is not None:
            self.entries[key] = count
            # rebuild heap lazily
            for i, (_, k) in enumerate(self.heap):
                if k == key:
                    self.heap[i] = (count, key)
                    heapq.heapify(self.heap)
                    return

        # not present
        if len(self.heap) < self.k:
            heapq.heappush(self.heap, (count, key))
            self.entries[key] = count
            return

        if self.heap[0][0] < count:
            # pop and add
            old = heapq.heappop(self.heap)
            try:
                del self.entries[old[1]]
            except KeyError:
                pass
            heapq.heappush(self.heap, (count, key))
            self.entries[key] = count

    def top(self) -> List[Dict[str, Any]]:
        return sorted([{"source_ip": k, "count": v} for k, v in self.entries.items()], key=lambda x: x["count"], reverse=True)


class DetectionEngine:
    def __init__(self) -> None:
        # Use deques for sliding time windows (efficient pops from left)
        self.failed_login_attempts: defaultdict[str, deque] = defaultdict(lambda: deque())
        # store (timestamp, port) tuples in deques per IP
        self.port_scan_events: defaultdict[str, deque] = defaultdict(lambda: deque())
        self.last_bruteforce_alert: Dict[str, datetime] = {}
        self.last_portscan_alert: Dict[str, datetime] = {}
        # TTL-based deduper to reduce duplicate detections flooding the UI
        self.dedupe = TimeDedupe(ttl_seconds=60)
        self._muted_ips: Dict[str, datetime] = {}
        # initialize content scanner (Aho-Corasick if available, otherwise fallback)
        self.scanner = ContentScanner(SQLI_PATTERNS)
        # Top-K & counting structures
        self.cms = CountMinSketch(width=256, depth=4)
        self.topk = TopK(k=10)
        # per-IP recent raw events for context / forensic playback
        self.context_store = defaultdict(lambda: deque(maxlen=CONTEXT_MAX))
        self._ingest_counter = itertools.count()
        self._events_seen = 0
        self._detection_totals: defaultdict[str, int] = defaultdict(int)

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        """Handle ISO8601 strings as well as raw epoch numbers from clients."""
        if not value:
            return datetime.utcnow()
        text = value.strip()
        # Accept integer / float Unix epochs alongside ISO8601 strings
        try:
            if text.replace(".", "", 1).isdigit():
                epoch = float(text)
                return datetime.utcfromtimestamp(epoch)
        except (ValueError, OSError):
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            return datetime.utcnow()

    def _cleanup_mutes(self) -> None:
        """Drop expired mute entries so memory stays tidy."""
        if not self._muted_ips:
            return
        now = datetime.utcnow()
        expired = [ip for ip, expiry in self._muted_ips.items() if expiry <= now]
        for ip in expired:
            self._muted_ips.pop(ip, None)

    def _is_muted(self, ip: str | None) -> bool:
        """Check whether an IP is currently silenced."""
        if not ip:
            return False
        self._cleanup_mutes()
        expiry = self._muted_ips.get(ip)
        if not expiry:
            return False
        if expiry <= datetime.utcnow():
            self._muted_ips.pop(ip, None)
            return False
        return True

    def mute(self, ip: str, duration_seconds: int) -> datetime:
        if duration_seconds <= 0:
            self._muted_ips.pop(ip, None)
            return datetime.utcnow()
        expiry = datetime.utcnow() + timedelta(seconds=duration_seconds)
        self._muted_ips[ip] = expiry
        return expiry

    def _persist_detection(self, detection: Dict[str, Any]) -> None:
        """Save the alert to disk and append a line to the human-readable log."""
        with _os_lock:
            append_event(EVENT_STORE_PATH, detection, MAX_EVENTS)

        line = json.dumps(detection, sort_keys=True)
        with _os_lock:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def process(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main entry point: accept a raw event and return any alerts it triggers."""
        timestamp = self._parse_timestamp(str(event.get("timestamp", "")))
        source_ip = str(event.get("source_ip", "unknown"))
        event_type = event.get("event_type")
        detections: List[Dict[str, Any]] = []
        self._events_seen += 1

        # update approximate counters for heavy-hitter detection
        try:
            self.cms.add(source_ip, 1)
            est = self.cms.estimate(source_ip)
            self.topk.maybe_add(source_ip, est)
        except Exception:
            # non-fatal for demo
            pass

        # store raw event for context with an ingest sequence for deterministic ordering
        try:
            context_event = dict(event)
            context_event.setdefault("timestamp", timestamp.isoformat(timespec="seconds") + "Z")
            context_event["_ingest_seq"] = next(self._ingest_counter)
            self.context_store[source_ip].append(context_event)
        except Exception:
            pass

        if event_type == "login_attempt":
            detections.extend(self._detect_bruteforce(event, source_ip, timestamp))
        elif event_type == "search":
            detection = self._detect_sql_injection(event, source_ip, timestamp)
            if detection:
                detections.append(detection)
        elif event_type == "port_probe":
            port = int(event.get("port", 0))
            path = event.get("path", "")
            detections.extend(self._detect_port_scan(source_ip, port, path, timestamp))

        for detection in detections:
            attack_type = detection.get("attack_type")
            if attack_type:
                self._detection_totals[attack_type] += 1
            self._detection_totals["events_total"] += 1
            self._persist_detection(detection)
            slack_notify(detection)
            _broadcast_detection(detection)
        return detections


    @app.route("/context/<path:ip>")
    def context_for_ip(ip: str) -> Any:
        """Return recent raw events for a given IP so the UI can show context."""
        try:
            items: List[Dict[str, Any]] = []
            if ip in detection_engine.context_store:
                raw_events: Iterable[Dict[str, Any]] = detection_engine.context_store[ip]
                sorted_events: List[Tuple[int, Dict[str, Any]]] = sorted(
                    ((event.get("_ingest_seq", 0), event) for event in raw_events),
                    key=lambda piece: piece[0],
                )
                items = [
                    {k: v for k, v in event.items() if k != "_ingest_seq"}
                    for _, event in sorted_events
                ]
            return jsonify({"ip": ip, "events": items})
        except Exception as exc:
            return jsonify({"ip": ip, "events": [], "error": str(exc)}), 500


    @app.route("/top", methods=["GET"])
    def top_offenders() -> Any:
        """Surface heavy-hitter IPs based on approximate counting structures."""
        try:
            top = detection_engine.topk.top()
            return jsonify({"top": top})
        except Exception as exc:
            return jsonify({"top": [], "error": str(exc)}), 500


    @app.route("/mute", methods=["POST"])
    def mute_ip() -> Any:
        """Temporarily silence alerts for an IP directly from the dashboard."""
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip") or request.args.get("ip")
        duration_raw = payload.get("duration") or payload.get("seconds") or request.args.get("dur")
        if not duration_raw:
            duration_raw = request.args.get("duration")
        try:
            duration = int(duration_raw) if duration_raw is not None else MUTE_DEFAULT_SECONDS
        except (TypeError, ValueError):
            duration = MUTE_DEFAULT_SECONDS
        if not ip:
            return jsonify({"status": "error", "message": "ip is required"}), 400
        expiry = detection_engine.mute(ip, duration)
        status = "muted" if duration > 0 else "unmuted"
        return jsonify(
            {
                "status": status,
                "ip": ip,
                "duration": duration,
                "expires_at": expiry.isoformat(timespec="seconds") + "Z",
            }
        )


    @app.route("/events/<path:alert_id>", methods=["GET"])
    def event_by_id(alert_id: str) -> Any:
        """Expose a single alert as JSON for API consumers or debugging."""
        event = _lookup_event(alert_id)
        if not event:
            return jsonify({"status": "not_found", "id": alert_id}), 404
        return jsonify(event)


    @app.route("/export/<path:alert_id>", methods=["GET"])
    def export_event(alert_id: str) -> Any:
        """Download the alert as a file so judges can see the payload."""
        event = _lookup_event(alert_id)
        if not event:
            return jsonify({"status": "not_found", "id": alert_id}), 404
        response = make_response(json.dumps(event, indent=2))
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = f"attachment; filename={alert_id}.json"
        return response

    def _detect_bruteforce(self, event: Dict[str, Any], source_ip: str, timestamp: datetime) -> List[Dict[str, Any]]:
        """Catch repeated failed logins within the configured sliding window."""
        if self._is_muted(source_ip):
            return []
        if event.get("success"):
            # clear any failed attempts on success
            self.failed_login_attempts.pop(source_ip, None)
            return []

        # sliding window using configured window seconds
        window_start = timestamp - timedelta(seconds=BRUTEFORCE_WINDOW_SECONDS)
        dq = self.failed_login_attempts[source_ip]
        # drop old timestamps
        while dq and dq[0] < window_start:
            dq.popleft()
        dq.append(timestamp)

        if len(dq) < BRUTEFORCE_THRESHOLD:
            return []

        last_alert = self.last_bruteforce_alert.get(source_ip)
        if last_alert and last_alert >= window_start:
            return []

        detection = self._build_detection(
            alert_type="brute_force",
            attack_type="Brute force login",
            severity="high",
            source_ip=source_ip,
            timestamp=timestamp,
            summary="Multiple failed logins were observed. This usually means someone is trying lots of passwords.",
            details={
                "attempt_count": len(dq),
                "window_seconds": BRUTEFORCE_WINDOW_SECONDS,
                "username": event.get("username", "unknown"),
            },
            meta={
                "count": len(dq),
                "window": BRUTEFORCE_WINDOW_SECONDS,
                "window_seconds": BRUTEFORCE_WINDOW_SECONDS,
                "threshold": BRUTEFORCE_THRESHOLD,
                "username": event.get("username", "unknown"),
                "path": event.get("path", "/login"),
            },
        )

        # dedupe similar alerts briefly using a key
        dedupe_key = f"bruteforce:{source_ip}:{detection['summary']}"
        if dedupe_key in self.dedupe:
            # already seen; avoid persisting duplicate alert
            return []
        self.dedupe.add(dedupe_key)

        self.last_bruteforce_alert[source_ip] = timestamp
        dq.clear()

        return [detection]

    def _detect_sql_injection(self, event: Dict[str, Any], source_ip: str, timestamp: datetime) -> Dict[str, Any] | None:
        """Look for obvious SQL injection patterns in search queries."""
        if self._is_muted(source_ip):
            return None
        query = str(event.get("query", ""))
        if not self.scanner.match(query):
            return None

        detection = self._build_detection(
            alert_type="sql_injection",
            attack_type="SQL injection",
            severity="medium",
            source_ip=source_ip,
            timestamp=timestamp,
            summary="A search request looked like it was trying to trick the database.",
            details={"query": event.get("query", "")},
            meta={
                "payload": event.get("query", ""),
                "path": event.get("path", "unknown"),
            },
        )

        dedupe_key = f"sqli:{source_ip}:{detection['details'].get('query','') }"
        if dedupe_key in self.dedupe:
            return None
        self.dedupe.add(dedupe_key)
        return detection

    def _detect_port_scan(self, source_ip: str, port: int, path: str, timestamp: datetime) -> List[Dict[str, Any]]:
        """Flag an IP that hits too many unique ports in a short burst."""
        if self._is_muted(source_ip):
            return []
        if port in PORTSCAN_IGNORE_PORTS:
            return []
        window_start = timestamp - timedelta(seconds=PORTSCAN_WINDOW_SECONDS)
        dq = self.port_scan_events[source_ip]
        # drop old entries
        while dq and dq[0][0] < window_start:
            dq.popleft()
        dq.append((timestamp, port))

        unique_ports = {p for (_, p) in dq}
        if len(unique_ports) < PORTSCAN_THRESHOLD:
            return []

        last_alert = self.last_portscan_alert.get(source_ip)
        if last_alert and last_alert >= window_start:
            return []

        detection = self._build_detection(
            alert_type="port_scan",
            attack_type="Port scan",
            severity="medium",
            source_ip=source_ip,
            timestamp=timestamp,
            summary="This machine is trying lots of different ports to see what is open.",
            details={
                "unique_ports": sorted(unique_ports),
                "window_seconds": PORTSCAN_WINDOW_SECONDS,
            },
            meta={
                "ports": len(unique_ports),
                "window": PORTSCAN_WINDOW_SECONDS,
                "path": path or "port_probe",
            },
        )

        dedupe_key = f"portscan:{source_ip}:{','.join(map(str, sorted(unique_ports)))}"
        if dedupe_key in self.dedupe:
            return []
        self.dedupe.add(dedupe_key)

        self.last_portscan_alert[source_ip] = timestamp
        dq.clear()

        return [detection]

    def _build_detection(
        self,
        *,
        alert_type: str,
        attack_type: str,
        severity: str,
        source_ip: str,
        timestamp: datetime,
        meta: Dict[str, Any],
        summary: str | None = None,
        details: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        payload_meta = dict(meta)
        payload_meta.setdefault("ip", source_ip)
        payload_meta.setdefault("source_ip", source_ip)
        payload_meta.setdefault("severity", severity)
        if details is not None:
            payload_meta.setdefault("details", details)
        if summary is not None:
            payload_meta.setdefault("summary", summary)

        alert = build_alert(alert_type, payload_meta)
        alert["attack_type"] = attack_type
        alert.setdefault("summary", summary or alert.get("explanation"))
        alert.setdefault("details", details or payload_meta.get("details", {}))
        alert.setdefault("timestamp", timestamp.isoformat(timespec="seconds") + "Z")
        return alert

    def _load_recent(self, n: int = 10) -> List[Dict[str, Any]]:
        """Return the most recent n persisted detections (from events.json)."""
        if not os.path.exists(EVENT_STORE_PATH):
            return []
        try:
            with open(EVENT_STORE_PATH, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return list(reversed(data))[:n]
        except Exception:
            return []
        return []

    def metrics_snapshot(self) -> Dict[str, Any]:
        """Expose counters so the dashboard can plot high-level stats."""
        snapshot = {
            "events_ingested": self._events_seen,
        }
        snapshot.update(self._detection_totals)
        return snapshot


def _load_events() -> List[Dict[str, Any]]:
    """Read the persisted events file, tolerating truncation or bad JSON."""
    if not os.path.exists(EVENT_STORE_PATH):
        return []
    try:
        with open(EVENT_STORE_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                return data[-MAX_EVENTS:]
    except json.JSONDecodeError:
        pass
    return []


detection_engine = DetectionEngine()
_persist_lock = threading.Lock()
_cached_events = _load_events()
# Quick lookup table for alerts so the dashboard can retrieve by ID instantly.
_event_index: Dict[str, Dict[str, Any]] = {
    event.get("id"): event for event in _cached_events if event.get("id")
}

def _lookup_event(alert_id: str) -> Dict[str, Any] | None:
    """Fetch a specific alert by ID from memory or fall back to disk."""
    with _persist_lock:
        event = _event_index.get(alert_id)
    if event:
        return event
    events = _load_events()
    for item in reversed(events):
        if item.get("id") == alert_id:
            return item
    return None

_sse_lock = threading.Lock()
_sse_subscribers: Set["queue.Queue[Dict[str, Any]]"] = set()  # who is listening for live updates


def _broadcast_detection(detection: Dict[str, Any]) -> None:
    """Push the alert to every connected Server-Sent Event subscriber."""
    with _sse_lock:
        dead: List["queue.Queue[Dict[str, Any]]"] = []
        for subscriber in _sse_subscribers:
            try:
                subscriber.put_nowait(detection)
            except queue.Full:
                dead.append(subscriber)
        for subscriber in dead:
            _sse_subscribers.discard(subscriber)


def _trim_cached_events() -> None:
    with _persist_lock:
        if len(_cached_events) > MAX_EVENTS:
            del _cached_events[:-MAX_EVENTS]
        valid_ids = {event.get("id") for event in _cached_events if event.get("id")}
        stale = [key for key in list(_event_index.keys()) if key not in valid_ids]
        for key in stale:
            _event_index.pop(key, None)


def _rotate_log_if_needed() -> None:
    """Rotate the text log once it exceeds the configured size."""
    if LOG_MAX_BYTES <= 0 or not os.path.exists(LOG_PATH):
        return
    try:
        if os.path.getsize(LOG_PATH) <= LOG_MAX_BYTES:
            return
    except OSError:
        return

    with _os_lock:
        backups = max(LOG_BACKUPS, 0)
        for index in range(backups, 0, -1):
            src = f"{LOG_PATH}.{index - 1}" if index > 1 else LOG_PATH
            dst = f"{LOG_PATH}.{index}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        # recreate the active log file
        try:
            open(LOG_PATH, "w", encoding="utf-8").close()
        except OSError:
            pass


def _maintenance_loop() -> None:
    """Background housekeeping: trim caches and rotate logs periodically."""
    interval = max(5, MAINTENANCE_INTERVAL_SECONDS)
    while True:
        time.sleep(interval)
        try:
            _trim_cached_events()
            _rotate_log_if_needed()
        except Exception:
            # background maintenance should never crash the process
            continue


_maintenance_thread = threading.Thread(target=_maintenance_loop, name="ids-maint", daemon=True)
_maintenance_thread.start()


@app.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({"status": "ok", "event_count": len(_cached_events)})


@app.route("/ingest", methods=["POST"])
def ingest() -> Any:
    """Receive a telemetry event from the demo app and run detections."""
    event = request.get_json(force=True)
    detections = detection_engine.process(event)
    if detections:
        with _persist_lock:
            for detection in detections:
                detection_id = detection.get("id")
                if detection_id:
                    _event_index[detection_id] = detection
            _cached_events.extend(detections)
            if len(_cached_events) > MAX_EVENTS:
                del _cached_events[:-MAX_EVENTS]
                valid_ids = {event.get("id") for event in _cached_events if event.get("id")}
                stale = [key for key in list(_event_index.keys()) if key not in valid_ids]
                for key in stale:
                    _event_index.pop(key, None)
    return jsonify({"status": "received", "detections": detections})


@app.route("/events", methods=["GET"])
def events() -> Any:
    with _persist_lock:
        events_sorted = sorted(_cached_events, key=lambda item: item.get("timestamp", ""), reverse=True)
    return jsonify({"events": events_sorted})


@app.route("/events/stream", methods=["GET"])
def events_stream() -> Any:
    def stream() -> Iterable[str]:
        subscriber: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=256)
        with _sse_lock:
            _sse_subscribers.add(subscriber)
        # send initial backlog
        with _persist_lock:
            snapshot = list(_cached_events)[-10:]
        for detection in snapshot:
            yield f"data: {json.dumps(detection)}\n\n"
        yield ": connected\n\n"
        try:
            while True:
                try:
                    detection = subscriber.get(timeout=15)
                    payload = json.dumps(detection)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with _sse_lock:
                _sse_subscribers.discard(subscriber)

    return app.response_class(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.route("/metrics", methods=["GET"])
def metrics() -> Any:
    snapshot = detection_engine.metrics_snapshot()
    with _persist_lock:
        snapshot.setdefault("events_total", len(_cached_events))
    return jsonify(snapshot)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)

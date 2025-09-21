from datetime import datetime

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Ensure tests don't mutate the repository event store: point IDS_PROXY_EVENTS
# at a temp file provided by pytest via the tmp_path fixture. We achieve this by
# setting the env var before importing the module. When pytest runs this file,
# the tmp_path fixture will be available in test functions and we lazily import
# the proxy module inside each test after configuring IDS_PROXY_EVENTS.
MOD_PATH = str(Path(__file__).resolve().parents[1] / "proxy.py")

def _load_proxy_with_events_path(events_path: str):
    """Helper to import the proxy module with IDS_PROXY_EVENTS pointing to events_path."""
    # Set env var first so module picks it up
    os.environ["IDS_PROXY_EVENTS"] = events_path
    sys.modules.pop("ids_proxy.proxy", None)
    spec = importlib.util.spec_from_file_location("ids_proxy.proxy", MOD_PATH)
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None
    loader.exec_module(module)
    return module


def make_event(event_type, source_ip="1.2.3.4", **kwargs):
    e = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event_type": event_type,
        "source_ip": source_ip,
    }
    e.update(kwargs)
    return e


@pytest.fixture()
def detection_engine(tmp_path):
    module = _load_proxy_with_events_path(str(tmp_path / "events.json"))
    engine = module.DetectionEngine()
    return engine


def test_bruteforce_detection(detection_engine):
    ip = "10.0.0.1"
    # send 5 failed attempts
    for _ in range(5):
        ev = make_event("login_attempt", source_ip=ip, username="admin", success=False)
        detection_engine.process(ev)
    # final process should have produced at least one detection in persisted store
    recent = detection_engine._load_recent(10)
    assert recent
    assert any(d.get("attack_type") == "Brute force login" for d in recent)
    latest = recent[0]
    assert latest.get("explanation")
    assert latest.get("remediation")
    assert latest.get("type") == "brute_force"


def test_sqli_detection(detection_engine):
    ev = make_event("search", source_ip="8.8.8.8", query="' OR 1=1 --")
    dets = detection_engine.process(ev)
    assert any(d.get("attack_type") == "SQL injection" for d in dets)
    assert dets
    enriched = dets[0]
    assert enriched.get("explanation")
    assert enriched.get("remediation")


def test_portscan_detection(detection_engine):
    ip = "192.0.2.9"
    # probe 10 unique ports
    for port in range(1000, 1010):
        ev = make_event("port_probe", source_ip=ip, port=port)
        detection_engine.process(ev)
    recent = detection_engine._load_recent(10)
    assert any(d.get("attack_type") == "Port scan" for d in recent)
    assert recent
    assert recent[0].get("remediation")

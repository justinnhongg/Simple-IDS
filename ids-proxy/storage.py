from __future__ import annotations

import json
import os
import tempfile
from typing import Any, List


def write_json_atomic(path: str, payload: Any) -> None:
    """Write payload to path using a temp file + atomic rename to avoid corruption."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix="events-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def append_event(path: str, event: Any, max_items: int) -> List[Any]:
    """Append event to a JSON list stored at path and return the new list."""
    events: List[Any] = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, list):
                events = loaded
        except json.JSONDecodeError:
            events = []
    events.append(event)
    if max_items > 0 and len(events) > max_items:
        events = events[-max_items:]
    write_json_atomic(path, events)
    return events

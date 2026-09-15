"""Opt-in event file sink in core/events.py (run harness enabler)."""
from __future__ import annotations

import json

from hacking_agent.core.events import EventBus


def test_sink_writes_json_lines(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("REYNARD_EVENT_LOG", str(path))
    bus = EventBus()
    bus.emit("tool_start", {"tool": "http_request"})
    bus.emit("finding", {"summary": "sqli"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first, second = json.loads(lines[0]), json.loads(lines[1])
    assert first["type"] == "tool_start" and first["id"] == 1
    assert second["payload"]["summary"] == "sqli"


def test_sink_default_off(tmp_path, monkeypatch):
    monkeypatch.delenv("REYNARD_EVENT_LOG", raising=False)
    bus = EventBus()
    bus.emit("x", {})
    # No file created anywhere under tmp; sink path stays unresolved.
    assert bus._sink_path is None
    assert list(tmp_path.iterdir()) == []


def test_sink_reopens_on_path_change(tmp_path, monkeypatch):
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    bus = EventBus()
    monkeypatch.setenv("REYNARD_EVENT_LOG", str(a))
    bus.emit("e1", {})
    monkeypatch.setenv("REYNARD_EVENT_LOG", str(b))
    bus.emit("e2", {})
    assert json.loads(a.read_text().splitlines()[0])["type"] == "e1"
    assert json.loads(b.read_text().splitlines()[0])["type"] == "e2"


def test_sink_creates_parent_dirs(tmp_path, monkeypatch):
    nested = tmp_path / "runs" / "abc" / "events.jsonl"
    monkeypatch.setenv("REYNARD_EVENT_LOG", str(nested))
    bus = EventBus()
    bus.emit("run_start", {"targets": ["https://x/"]})
    assert nested.exists()

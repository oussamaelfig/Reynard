"""UI accessibility contracts and a local preview that cannot launch research."""
from __future__ import annotations

from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "src" / "hacking_agent" / "harness" / "ui" / "index.html"


class Document(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.elements: list[dict] = []
        self.stack: list[dict] = []
        self.script_text: list[str] = []
        self.duplicate_attributes: list[tuple[str, str]] = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        seen = set()
        for name, _value in attrs:
            if name in seen:
                self.duplicate_attributes.append((tag, name))
            seen.add(name)
        element = {"tag": tag, "attrs": dict(attrs), "ancestors": list(self.stack)}
        self.elements.append(element)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(element)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if self.stack and self.stack[-1]["tag"] == "script":
            if self.stack[-1]["attrs"].get("type", "") not in {"application/json", "application/ld+json"}:
                self.script_text.append(data)

    @property
    def ids(self):
        return {element["attrs"]["id"]: element for element in self.elements if "id" in element["attrs"]}


@pytest.fixture
def document():
    return Document(UI.read_text(encoding="utf-8"))


def test_ui_landmarks_unique_ids_live_feedback_and_reduced_motion(document):
    assert not document.duplicate_attributes, "Duplicate attributes create ambiguous browser behavior"
    ids = [element["attrs"]["id"] for element in document.elements if "id" in element["attrs"]]
    assert len(ids) == len(set(ids)), "Duplicate IDs break labels, focus, and tab relationships"
    main = [element for element in document.elements if element["tag"] == "main"]
    assert len(main) == 1 and main[0]["attrs"].get("id")
    assert any(element["tag"] == "nav" and (
        element["attrs"].get("aria-label") or element["attrs"].get("aria-labelledby")
    ) for element in document.elements)
    skip = next(element for element in document.elements
                if element["tag"] == "a" and element["attrs"].get("class") == "skip-link")
    destination = document.ids[skip["attrs"]["href"].removeprefix("#")]
    assert destination["attrs"].get("tabindex") == "-1"
    assert destination["tag"] == "h1", "Skip to the workspace heading, visible in every view"
    assert not any(parent["attrs"].get("class") in {"detail", "findings-view", "list-col"}
                   for parent in destination["ancestors"]), "Do not skip to a responsive-hidden pane"
    assert any(element["attrs"].get("aria-live") in {"polite", "assertive"}
               for element in document.elements)
    assert any(element["attrs"].get("role") == "alert" for element in document.elements)
    styles = UI.read_text(encoding="utf-8")
    stylesheet = UI.with_name("console.css")
    if stylesheet.exists():
        styles += stylesheet.read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in styles


def test_ui_inputs_have_programmatic_labels(document):
    labels = {element["attrs"]["for"] for element in document.elements
              if element["tag"] == "label" and element["attrs"].get("for")}
    missing = []
    for element in document.elements:
        attrs = element["attrs"]
        if element["tag"] not in {"input", "textarea", "select"} or attrs.get("type") in {"hidden", "submit", "button"}:
            continue
        wrappers = [parent for parent in element["ancestors"] if parent["tag"] == "label"]
        for wrapper in wrappers:
            target = wrapper["attrs"].get("for")
            assert target is None or target == attrs.get("id"), "A wrapping label must name its own control"
        wrapped = bool(wrappers)
        named = attrs.get("id") in labels or wrapped or bool(attrs.get("aria-label"))
        if attrs.get("aria-labelledby"):
            named = all(reference in document.ids for reference in attrs["aria-labelledby"].split())
        if not named:
            missing.append(attrs.get("id", element["tag"]))
    assert not missing, f"Inputs need labels: {missing}"
    assert labels <= document.ids.keys(), "Every label's for target must exist"


def test_ui_retains_explicit_authorization_and_positive_timeout(document):
    authorization = document.ids["f-authorized"]["attrs"]
    assert authorization.get("type") == "checkbox"
    assert "required" in authorization and "checked" not in authorization
    assert "checked" not in document.ids["f-destructive"]["attrs"]
    assert float(document.ids["f-timeout"]["attrs"]["min"]) > 0
    submit = document.ids["f-submit"]
    assert submit["tag"] == "button" and submit["attrs"].get("type") == "submit"
    form_id = submit["attrs"]["form"]
    assert document.ids[form_id]["tag"] == "form"
    assert document.ids[form_id] in document.ids["f-authorized"]["ancestors"]
    assert "required" not in document.ids["f-targets"]["attrs"], "Authorized-domain-only launches must remain possible"
    token = document.ids["login-token"]["attrs"]
    assert token.get("type") == "password" and "required" in token


def test_ui_uses_local_script_and_no_inline_event_handlers_or_external_resources(document):
    assert not "".join(document.script_text).strip(), "Executable UI code belongs in console.js"
    scripts = [element for element in document.elements if element["tag"] == "script"]
    assert any(element["attrs"].get("src", "").endswith("console.js") for element in scripts)
    for element in document.elements:
        attrs = element["attrs"]
        assert not any(name.lower().startswith("on") for name in attrs), element
        if element["tag"] in {"script", "img", "iframe", "link"}:
            resource = attrs.get("src") or attrs.get("href") or ""
            assert not resource.startswith(("http:", "https:", "//")), resource
    source = UI.read_text(encoding="utf-8")
    assert "fonts.googleapis.com" not in source and "googletagmanager" not in source


def test_ui_tabs_and_dialogs_have_accessible_relationships(document):
    tabs = [element for element in document.elements if element["attrs"].get("role") == "tab"]
    assert tabs and any(element["attrs"].get("role") == "tablist" for element in document.elements)
    for tab in tabs:
        attrs = tab["attrs"]
        assert tab["tag"] == "button" and attrs.get("aria-selected") in {"true", "false"}
        panel = document.ids[attrs["aria-controls"]]
        assert panel["attrs"].get("role") == "tabpanel"
        assert panel["attrs"].get("aria-labelledby") == attrs["id"]
    dialogs = [element for element in document.elements
               if element["tag"] == "dialog" or element["attrs"].get("role") == "dialog"]
    assert dialogs
    for dialog in dialogs:
        attrs = dialog["attrs"]
        assert attrs.get("aria-label") or attrs.get("aria-labelledby") in document.ids


def _preview_module():
    name = "preview_harness_ui"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_preview_is_isolated_and_cannot_construct_workers(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from hacking_agent.harness import server

    preview = _preview_module()
    operator_state = tmp_path / "operator-state"
    monkeypatch.setenv("REYNARD_VALIDATION_STATE_DIR", str(operator_state))
    monkeypatch.setenv("REYNARD_VALIDATION_HMAC_KEY", "do-not-use-operator-key")
    monkeypatch.setenv("REYNARD_HOST_EXEC", "1")

    def forbidden(*args, **kwargs):
        pytest.fail("The preview must not start workers or subprocesses")

    monkeypatch.setattr(server, "JobManager", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    with preview.preview_app() as app:
        assert app.state.preview
        root = app.state.preview_root
        assert root != operator_state and root.exists()
        with TestClient(app, base_url="http://127.0.0.1") as client:
            assert client.get("/api/runs").status_code == 401
            assert preview.PREVIEW_TOKEN not in client.get("/").text
            assert client.post("/api/session", headers={"x-harness-token": preview.PREVIEW_TOKEN}).status_code == 200
            rows = client.get("/api/runs").json()
            assert len(rows) == 4
            assert {row["status"] for row in rows} == {"running", "completed", "failed"}
            assert all("[DEMO]" in row["description"] for row in rows)
            findings = client.get("/api/findings").json()
            assert findings["confirmed_count"] == 1
            assert findings["findings"][0]["title"].startswith("[DEMO]")
            assert sum(row["verified_count"] for row in rows) == 1
            completed = preview.SEED_IDS["completed"]
            report = client.get(f"/api/runs/{completed}/report").json()
            assert report["json"]["confirmed_count"] == 1
            assert "DEMO" in report["markdown"]
            clean = client.get(f"/api/runs/{preview.SEED_IDS['clean']}/report").json()
            assert clean["json"]["confirmed_count"] == 0
            events = [json.loads(line) for line in app.state.store.events_path(preview.SEED_IDS["running"]).read_text().splitlines()]
            assert all(event["payload"]["demo"] for event in events)
            assert {event["type"] for event in events} >= {"run_start", "tool_result", "reasoning_note"}
            # The demo must use the actual provenance gate, not a fixture-specific bypass.
            _markdown_path, json_path = app.state.store.report_paths(completed)
            raw = json.loads(json_path.read_text(encoding="utf-8"))
            raw["targets_assessed"][0]["findings"][0]["title"] = "UNSIGNED PREVIEW MUTATION"
            json_path.write_text(json.dumps(raw), encoding="utf-8")
            assert client.get("/api/findings").json()["confirmed_count"] == 0
            tampered = client.get(f"/api/runs/{completed}/report").json()
            assert tampered["json"]["confirmed_count"] == 0
            assert "UNSIGNED PREVIEW MUTATION" not in tampered["markdown"]
    assert not root.exists() and not operator_state.exists()
    assert os.environ["REYNARD_VALIDATION_STATE_DIR"] == str(operator_state)
    assert os.environ["REYNARD_VALIDATION_HMAC_KEY"] == "do-not-use-operator-key"
    assert os.environ["REYNARD_HOST_EXEC"] == "1"


@pytest.mark.parametrize("targets", [None, ["https://app.example.test/"]], ids=["domains-only", "explicit-target"])
def test_preview_launch_and_cancel_are_state_only_and_authorization_still_applies(monkeypatch, targets):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from hacking_agent.harness import server

    def forbidden(*args, **kwargs):
        pytest.fail("Fixture launches must not construct workers or connect to targets")

    monkeypatch.setattr(server, "JobManager", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)

    preview = _preview_module()
    with preview.preview_app(empty=True) as app:
        with TestClient(app, base_url="http://127.0.0.1") as client:
            client.post("/api/session", headers={"x-harness-token": preview.PREVIEW_TOKEN})
            assert client.get("/api/runs").json() == []
            assert client.get("/api/findings").json()["confirmed_count"] == 0
            invalid = {"authorized_domains": ["app.example.test"], "authorized": False}
            assert client.post("/api/runs", json=invalid).status_code == 400
            assert app.state.jobs.submitted == []
            valid = {**invalid, "authorized": True}
            if targets is not None:
                valid["targets"] = targets
            response = client.post("/api/runs", json=valid)
            assert response.status_code == 201
            run_id = response.json()["run_id"]
            assert app.state.jobs.submitted == [run_id]
            assert app.state.store.load_request(run_id).resolved_targets() == ["https://app.example.test/"]
            assert client.get(f"/api/runs/{run_id}").json()["status"] == "running"
            assert client.get(f"/api/runs/{run_id}").json()["description"].startswith("[DEMO]")
            assert "No worker" in client.get(f"/api/runs/{run_id}/log").text
            assert client.post(f"/api/runs/{run_id}/cancel").json() == {"cancelled": True}
            assert client.get(f"/api/runs/{run_id}").json()["status"] == "cancelled"


def test_preview_cli_binds_only_loopback_and_never_starts_without_main(monkeypatch):
    pytest.importorskip("fastapi")
    import uvicorn

    preview = _preview_module()
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    assert preview.main(["--empty", "--port", "8892"]) == 0
    assert calls == [{"host": "127.0.0.1", "port": 8892, "log_level": "warning",
                      "timeout_graceful_shutdown": 2}]
    with pytest.raises(SystemExit):
        preview.main(["--host", "0.0.0.0"])

"""Authorized client-assessment workflow.

``reynard-assess`` runs a scoped recon -> enumerate -> per-target test ->
aggregated client report flow against the assets declared in an engagement
config, honoring the rules of engagement (authorized scope, out-of-scope
denylist, request rate limit / cap, destructive-action policy, testing window).

It reuses the existing multi-agent Orchestrator programmatically (like the
``--live`` path in ``lab_eval``) — it does not restructure the core loop. Each
authorized target is tested by its own Orchestrator whose ScopeGuard has the
engagement attached, and the per-target findings are aggregated into a single
consolidated client report (Markdown + JSON) under ``logs/`` (or ``--out``).

Safety: the command refuses to run unless the engagement declares an authorized
scope. The scope/rate-limit/CVSS/report logic is unit-tested offline; this
module never attacks anything on its own.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from hacking_agent.agents.reporter import (
    Finding,
    extract_findings,
    finding_to_report_dict,
    render_assessment_report,
)
from hacking_agent.core.engagement import Engagement, EngagementError, load_engagement
from hacking_agent.core.finding_validation import (
    REPORTABILITY_SCHEMA_VERSION,
    emit_suppression,
    partition_reportable,
)
from hacking_agent.core.evidence_bundle import sanitize_text
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
from hacking_agent.core.process_control import stop_process_tree
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core.validation_provenance import (
    attest_report,
    canonical_json,
    sha256_text,
)

console = Console()


def _engagement_binding(engagement: Engagement) -> str:
    return "engagement:" + sha256_text(canonical_json({
        "name": engagement.engagement_name,
        "authorized_domains": sorted(engagement.authorized_domains),
        "authorized_cidrs": sorted(engagement.authorized_cidrs),
        "authorized_url_prefixes": sorted(
            engagement.authorized_url_prefixes
        ),
        "out_of_scope": sorted(engagement.out_of_scope),
    }))[:24]


def authorized_targets(
    engagement: Engagement,
    explicit: list[str] | None = None,
) -> list[str]:
    """Resolve the list of target URLs to assess from an engagement.

    Refuses (raises ``EngagementError``) when no authorized scope is declared —
    a scope-less engagement is not authorization to test anything. Explicit
    ``--target`` URLs are honored but must fall within the authorized scope and
    outside the out-of-scope denylist.
    """
    if not engagement.has_authorized_scope():
        raise EngagementError(
            "Refusing to run: the engagement declares no authorized scope "
            "(authorized_domains / authorized_cidrs / authorized_url_prefixes). "
            "Define an authorized scope before running an assessment."
        )

    guard = ScopeGuard.from_engagement(engagement)
    targets: list[str] = []

    def _add(raw: str) -> None:
        url = raw.strip() if "://" in raw else f"https://{raw.strip()}"
        try:
            parsed = urlparse(url)
            valid = (
                parsed.scheme in {"http", "https"}
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and guard.is_in_scope(url)
            )
        except ValueError:
            valid = False
        if not valid:
            console.print(f"[yellow]Skipping invalid/out-of-scope target: {raw}[/]")
            return
        if url not in targets:
            targets.append(url)

    if explicit:
        for raw in explicit:
            _add(raw)
    else:
        for domain in engagement.authorized_domains:
            host = domain.strip().lower()
            if host:
                _add(f"https://{host}/")
        for prefix in engagement.authorized_url_prefixes:
            p = (prefix or "").strip()
            if p and p not in targets:
                _add(p)

    if not targets:
        raise EngagementError(
            "No assessable targets: authorized scope resolved to an empty target "
            "list (only CIDRs, or all targets out-of-scope). Pass --target URL."
        )
    return targets


def _engagement_meta(engagement: Engagement, targets: list[str]) -> dict[str, Any]:
    window = ""
    if engagement.testing_window_start or engagement.testing_window_end:
        window = f"{engagement.testing_window_start or '...'} → {engagement.testing_window_end or '...'}"
    return {
        "engagement_name": sanitize_text(
            engagement.engagement_name or "Authorized Assessment"
        ),
        "client": sanitize_text(engagement.client),
        "tester": sanitize_text(engagement.tester),
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "targets": [sanitize_text(str(value)) for value in targets],
        "authorized_domains": [
            sanitize_text(str(value)) for value in engagement.authorized_domains
        ],
        "authorized_cidrs": [
            sanitize_text(str(value)) for value in engagement.authorized_cidrs
        ],
        "out_of_scope": [
            sanitize_text(str(value)) for value in engagement.out_of_scope
        ],
        "testing_window": sanitize_text(window),
    }


def run_target(
    engagement: Engagement,
    target_url: str,
    *,
    max_iterations: int,
    per_target_timeout: float,
    objective: str | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    """Run one target in an isolated process, joining it before returning.

    A timeout discards incomplete findings and terminates the owned host process
    tree. Already submitted container/external jobs may need separate cleanup;
    assessment callers must stop scheduling further targets on timeout.
    """
    if not math.isfinite(per_target_timeout) or per_target_timeout < 0:
        raise ValueError("per_target_timeout must be finite and nonnegative")
    if not isinstance(max_iterations, int) or isinstance(max_iterations, bool) or max_iterations < 1:
        raise ValueError("max_iterations must be a positive integer")
    target_url = authorized_targets(engagement, [target_url])[0]
    if not engagement.is_within_window():
        raise EngagementError("Refusing to run outside the engagement testing window")
    console.print(f"[bold cyan]▶ Assessing target:[/] {target_url}")
    started = time.monotonic()
    timed_out = False
    row: dict[str, Any] = {}
    from hacking_agent.core import sessions

    registry = sessions._REGISTRY
    session_snapshot = {
        "sessions": [registry.get(name).to_transfer_dict() for name in registry.names()],
        "active": registry.active().name,
    } if registry is not None else {}
    with tempfile.TemporaryDirectory(prefix="reynard-target-") as workspace:
        result_path = Path(workspace) / "result.json"
        config = json.dumps({
            "engagement": asdict(engagement),
            "target_url": target_url,
            "max_iterations": max_iterations,
            "objective": objective,
            "session_snapshot": session_snapshot,
            "run_id": run_id or os.getenv("REYNARD_RUN_ID", ""),
            "engagement_id": os.getenv("REYNARD_ENGAGEMENT_ID") or _engagement_binding(engagement),
        })
        proc = subprocess.Popen(
            [sys.executable, "-m", "hacking_agent.cli.assess_worker",
             str(result_path)],
            start_new_session=(os.name != "nt"),
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        previous_sigterm = None
        if os.name != "nt" and threading.current_thread() is threading.main_thread():
            # A harness cancellation sends SIGTERM to this parent group. The
            # target has its own session, so unwind through its cleanup first.
            def interrupted(signum: int, _frame: Any) -> None:
                raise SystemExit(128 + signum)
            previous_sigterm = signal.signal(signal.SIGTERM, interrupted)
        try:
            proc.communicate(input=config, timeout=per_target_timeout or None)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_process_tree(proc)
        except BaseException:
            stop_process_tree(proc)
            raise
        finally:
            if previous_sigterm is not None:
                signal.signal(signal.SIGTERM, previous_sigterm)
            if proc.stdin is not None:
                proc.stdin.close()
        if not timed_out:
            try:
                if proc.returncode != 0:
                    raise RuntimeError(f"target worker exited with code {proc.returncode}")
                row = json.loads(result_path.read_text(encoding="utf-8"))
                if not isinstance(row, dict):
                    raise ValueError("target worker result must be an object")
                verdict = row.get("verdict")
                if not isinstance(verdict, str) or not (verdict == "assessed" or verdict.startswith("error:")):
                    raise ValueError("target worker result has an invalid verdict")
                if not isinstance(row.get("findings"), list):
                    raise ValueError("target worker result has invalid findings")
                row["findings"] = (
                    [Finding(**item) for item in row["findings"]]
                    if verdict == "assessed" else []
                )
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                row = {"verdict": f"error: {str(exc)[:200]}", "findings": []}
    return {
        "target": target_url,
        "verdict": f"timeout after {per_target_timeout}s" if timed_out else row.get("verdict", "error: worker result missing"),
        "timed_out": timed_out,
        "wall_clock_seconds": round(time.monotonic() - started, 1),
        "findings": [] if timed_out else row.get("findings", []),
    }


def _run_target_worker(config: dict[str, Any]) -> dict[str, Any]:
    """Worker-only entry point; never construct a live orchestrator in the parent."""
    engagement = Engagement(**config["engagement"])
    target_url = authorized_targets(engagement, [config["target_url"]])[0]
    if not engagement.is_within_window():
        raise EngagementError("Refusing to run outside the engagement testing window")
    snapshot = config.get("session_snapshot") or {}
    if snapshot:
        from hacking_agent.core import sessions

        registry = sessions.get_registry()
        for session in snapshot.get("sessions", []):
            registry.register(sessions.AuthSession.from_transfer_dict(session), overwrite=True)
        registry.set_active(snapshot.get("active", "default"))
    from hacking_agent.cli.orchestrator import Orchestrator

    orch = Orchestrator(
        target_url=target_url,
        max_iterations=config["max_iterations"],
        objective=(config.get("objective") or "").strip() or (
            "Authorized security assessment: recon, enumerate, and test the "
            "in-scope target for exploitable vulnerabilities, then produce "
            "evidence-backed findings."
        ),
        scope_domains=list(engagement.authorized_domains),
        scope_cidrs=list(engagement.authorized_cidrs),
        mission_mode="production",
        engagement=engagement,
        engagement_id=config.get("engagement_id") or _engagement_binding(engagement),
        run_id=config.get("run_id", ""),
    )
    result = orch.run()
    if result is None or result.success is not True:
        return {"verdict": "error: orchestrator did not complete a successful report", "findings": []}
    orch._assemble_evidence_bundles()
    findings = extract_findings(orch.memory, orch.evidence, orch.bundles)
    return {"verdict": "assessed", "findings": [asdict(item) for item in findings]}


def build_consolidated_report(
    engagement: Engagement,
    targets: list[str],
    target_results: list[dict[str, Any]],
    *,
    run_id: str = "",
    engagement_id: str = "",
) -> tuple[str, dict[str, Any]]:
    """Aggregate per-target results into a consolidated report (md + json)."""
    meta = _engagement_meta(engagement, targets)
    all_candidates: list[Finding] = []
    for row in target_results:
        all_candidates.extend(row.get("findings", []))
    all_findings, suppressed = partition_reportable(all_candidates)
    for finding, decision in suppressed:
        emit_suppression(finding, decision)

    target_summaries = []
    for row in target_results:
        confirmed_row, suppressed_row = partition_reportable(
            row.get("findings", [])
        )
        verdict = str(row.get("verdict") or "").lower()
        status = (
            "error" if verdict.startswith("error:")
            else "timeout" if verdict.startswith("timeout")
            else "assessed"
        )
        target_summaries.append({
            "target": sanitize_text(str(row.get("target", ""))),
            "status": status,
            "confirmed_count": len(confirmed_row),
            "suppressed_count": len(suppressed_row),
            "wall_clock_seconds": row.get("wall_clock_seconds", 0),
        })

    report_md = render_assessment_report(
        {**meta, "target_summaries": target_summaries},
        all_candidates,
    )

    serialized_rows: list[dict[str, Any]] = []
    for row in target_results:
        row_confirmed, row_suppressed = partition_reportable(
            row.get("findings", [])
        )
        verdict_text = str(row.get("verdict") or "").lower()
        verdict = (
            "error" if verdict_text.startswith("error:")
            else "timeout" if verdict_text.startswith("timeout")
            else "assessed" if verdict_text == "assessed"
            else "failed" if verdict_text == "failed"
            else "cancelled" if verdict_text == "cancelled"
            else "unknown"
        )
        serialized = [finding_to_report_dict(item) for item in row_confirmed]
        serialized_rows.append({
            "target": (
                serialized[0]["target"] if serialized
                else sanitize_text(str(row.get("target") or ""))
            ),
            "verdict": verdict,
            "wall_clock_seconds": max(
                0.0, float(row.get("wall_clock_seconds", 0) or 0)
            ),
            "findings": serialized,
            "confirmed_count": len(serialized),
            "suppressed_count": len(row_suppressed),
        })

    report_json: dict[str, Any] = {
        **meta,
        "reportability_policy_version": REPORTABILITY_SCHEMA_VERSION,
        "target_count": len(targets),
        "finding_count": len(all_findings),
        "verified_count": len(all_findings),
        "confirmed_count": len(all_findings),
        "suppressed_count": len(suppressed),
        "suppression_semantics": (
            "report candidates rejected by the customer export gate"
        ),
        "targets_assessed": serialized_rows,
    }
    report_run_id = (
        os.getenv("REYNARD_RUN_ID")
        or run_id
        or f"assessment:{uuid.uuid4().hex}"
    )
    report_engagement_id = (
        os.getenv("REYNARD_ENGAGEMENT_ID")
        or engagement_id
        or _engagement_binding(engagement)
    )
    report_json["report_authenticity"] = attest_report(
        report_json,
        run_id=report_run_id,
        engagement_id=report_engagement_id,
        validator_instance_id=f"reporter:{uuid.uuid4().hex}",
    )
    return report_md, report_json


def write_reports(
    report_md: str,
    report_json: dict[str, Any],
    out_dir: str | None,
) -> tuple[Path, Path]:
    """Re-gate and write the consolidated report (default ``logs/``).

    ``report_md`` is retained in the signature for compatibility, but the
    customer Markdown is deterministically rebuilt from the sanitized JSON so
    a stale or caller-supplied Markdown body cannot bypass the finding gate.
    """
    from hacking_agent.harness.submission import (
        render_stored_report_markdown,
        sanitize_report_json,
    )

    safe_json = sanitize_report_json(report_json)
    safe_markdown = render_stored_report_markdown(report_json)
    if out_dir:
        base = Path(out_dir)
        base.mkdir(parents=True, exist_ok=True)
    else:
        ensure_runtime_dirs()
        base = LOG_DIR
    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
    md_path = base / f"assessment_{ts}.md"
    json_path = base / f"assessment_{ts}.json"
    md_path.write_text(safe_markdown, encoding="utf-8")
    json_path.write_text(json.dumps(safe_json, indent=2), encoding="utf-8")
    return md_path, json_path


def run_assessment(args: argparse.Namespace) -> int:
    """Load the engagement, resolve targets, run each, and write the report."""
    if (not math.isfinite(args.per_target_timeout) or args.per_target_timeout < 0
            or args.max_iterations < 1):
        console.print("[red]Iterations must be positive and timeout finite/nonnegative.[/]")
        return 2
    bounty_source = getattr(args, "bounty_scope", None)
    if not args.engagement and not bounty_source:
        console.print("[red]Provide --engagement or --bounty-scope.[/]")
        return 2
    try:
        if bounty_source:
            # Bug-bounty program scope -> Engagement (offline file or, when
            # HackerOne credentials are set, the HackerOne API). This only
            # PRODUCES the engagement; ScopeGuard remains the sole authority.
            from hacking_agent.integrations.bounty import (
                BountyScopeError, build_engagement_from_source,
            )
            try:
                engagement = build_engagement_from_source(bounty_source)
            except BountyScopeError as exc:
                console.print(f"[red]Bounty scope error: {exc}[/]")
                return 2
            console.print(
                f"[dim]Imported bounty scope from {bounty_source}: "
                f"{len(engagement.authorized_domains)} in-scope domain(s), "
                f"{len(engagement.out_of_scope)} out-of-scope.[/]"
            )
        else:
            engagement = load_engagement(args.engagement)
    except EngagementError as exc:
        console.print(f"[red]Engagement config error: {exc}[/]")
        return 2

    if not engagement.is_within_window():
        console.print(
            "[red]Refusing to run: current time is outside the engagement "
            f"testing window ({engagement.testing_window_start} → "
            f"{engagement.testing_window_end}).[/]"
        )
        return 2

    try:
        targets = authorized_targets(engagement, explicit=args.target)
    except EngagementError as exc:
        console.print(f"[red]{exc}[/]")
        return 2

    console.print(f"[bold]Engagement:[/] {engagement.summary()}")
    console.print(f"[bold]Targets:[/] {targets}")

    assessment_run_id = (
        os.getenv("REYNARD_RUN_ID")
        or f"assessment:{uuid.uuid4().hex}"
    )
    assessment_engagement_id = (
        os.getenv("REYNARD_ENGAGEMENT_ID")
        or _engagement_binding(engagement)
    )
    target_results: list[dict[str, Any]] = []
    if args.dry_run:
        console.print("[yellow]--dry-run: skipping live testing.[/]")
    else:
        for target in targets:
            target_results.append(
                run_target(
                    engagement,
                    target,
                    max_iterations=args.max_iterations,
                    per_target_timeout=args.per_target_timeout,
                    run_id=assessment_run_id,
                )
            )
            if target_results[-1].get("timed_out"):
                console.print("[yellow]Stopping assessment after target timeout; review outstanding container work before retrying.[/]")
                break

    report_md, report_json = build_consolidated_report(
        engagement,
        targets,
        target_results,
        run_id=assessment_run_id,
        engagement_id=assessment_engagement_id,
    )
    md_path, json_path = write_reports(report_md, report_json, args.out)
    console.print(f"[green bold]📄 Consolidated report:[/] {md_path}")
    console.print(f"[green]   📊 JSON:[/] {json_path}")
    return int(any(row.get("timed_out") or str(row.get("verdict", "")).startswith("error:")
                   for row in target_results))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reynard-assess",
        description=(
            "Run an authorized client assessment: scoped recon -> enumerate -> "
            "per-target test -> consolidated client report, gated by an "
            "engagement config's rules of engagement."
        ),
    )
    parser.add_argument(
        "--engagement",
        default=None,
        help="Engagement config file (YAML or JSON). See eval/engagement.sample.yaml.",
    )
    parser.add_argument(
        "--bounty-scope",
        default=None,
        help=(
            "Bug-bounty program scope source: a structured scope file "
            "(YAML/JSON) OR 'hackerone:<program-handle>' to import structured "
            "scopes from the HackerOne API (requires HACKERONE_API_USERNAME + "
            "HACKERONE_API_TOKEN). Alternative to --engagement."
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output directory for the consolidated report (default: logs/).",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=None,
        help="Explicit in-scope target URL (repeatable). Overrides domain-derived targets.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=int(os.getenv("MAX_ITERATIONS", "30")),
        help="Per-target max specialist dispatches.",
    )
    parser.add_argument(
        "--per-target-timeout",
        type=float,
        default=float(os.getenv("ASSESS_PER_TARGET_TIMEOUT", "1800")),
        help="Per-target wall-clock timeout in seconds (0 = no timeout).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate scope + write an empty report without testing anything.",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.per_target_timeout) or args.per_target_timeout < 0:
        parser.error("--per-target-timeout must be finite and nonnegative")
    if args.max_iterations < 1:
        parser.error("--max-iterations must be positive")
    return args


def main() -> None:
    args = parse_args()
    from dotenv import load_dotenv

    from hacking_agent.core.paths import ENV_FILE
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)
    raise SystemExit(run_assessment(args))


if __name__ == "__main__":
    main()

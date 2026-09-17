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
import subprocess
import sys
import tempfile
import time
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
    emit_suppression,
    partition_reportable,
)
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
from hacking_agent.core.process_control import stop_process_tree
from hacking_agent.core.scope import ScopeGuard

console = Console()


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
        "engagement_name": engagement.engagement_name or "Authorized Assessment",
        "client": engagement.client,
        "tester": engagement.tester,
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "targets": targets,
        "authorized_domains": engagement.authorized_domains,
        "authorized_cidrs": engagement.authorized_cidrs,
        "out_of_scope": engagement.out_of_scope,
        "testing_window": window,
    }


def run_target(
    engagement: Engagement,
    target_url: str,
    *,
    max_iterations: int,
    per_target_timeout: float,
    objective: str | None = None,
) -> dict[str, Any]:
    """Run one target in an isolated process, joining it before returning.

    A timeout discards incomplete findings and terminates the owned host process
    tree. Already submitted container/external jobs may need separate cleanup;
    assessment callers must stop scheduling further targets on timeout.
    """
    if not math.isfinite(per_target_timeout) or per_target_timeout < 0:
        raise ValueError("per_target_timeout must be finite and nonnegative")
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
        "sessions": [asdict(registry.get(name)) for name in registry.names()],
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
        })
        proc = subprocess.Popen(
            [sys.executable, "-m", "hacking_agent.cli.assess_worker",
             str(result_path)],
            start_new_session=(os.name != "nt"),
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        try:
            proc.communicate(input=config, timeout=per_target_timeout or None)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_process_tree(proc)
        except BaseException:
            stop_process_tree(proc)
            raise
        if not timed_out:
            try:
                if proc.returncode != 0:
                    raise RuntimeError(f"target worker exited with code {proc.returncode}")
                row = json.loads(result_path.read_text(encoding="utf-8"))
                row["findings"] = [Finding(**item) for item in row.get("findings", [])]
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
            registry.register(sessions.AuthSession(**session), overwrite=True)
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
    )
    orch.scope_guard.attach_engagement(engagement)
    orch.run()
    orch._assemble_evidence_bundles()
    findings = extract_findings(orch.memory, orch.evidence, orch.bundles)
    return {"verdict": "assessed", "findings": [asdict(item) for item in findings]}


def build_consolidated_report(
    engagement: Engagement,
    targets: list[str],
    target_results: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Aggregate per-target results into a consolidated report (md + json)."""
    meta = _engagement_meta(engagement, targets)
    all_candidates: list[Finding] = []
    for row in target_results:
        all_candidates.extend(row.get("findings", []))
    all_findings, suppressed = partition_reportable(all_candidates)
    reason_counts: dict[str, int] = {}
    for finding, decision in suppressed:
        reason_counts[decision.reason_code] = (
            reason_counts.get(decision.reason_code, 0) + 1
        )
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
            "target": row.get("target", ""),
            "status": status,
            "confirmed_count": len(confirmed_row),
            "suppressed_count": len(suppressed_row),
            "wall_clock_seconds": row.get("wall_clock_seconds", 0),
        })

    report_md = render_assessment_report(
        {**meta, "target_summaries": target_summaries},
        all_candidates,
    )

    report_json = {
        **meta,
        "reportability_policy_version": 1,
        "target_count": len(targets),
        "finding_count": len(all_findings),
        "verified_count": len(all_findings),
        "confirmed_count": len(all_findings),
        "suppressed_count": len(suppressed),
        "suppression_reasons": reason_counts,
        "targets_assessed": [
            {
                "target": row["target"],
                "verdict": row["verdict"],
                "wall_clock_seconds": row["wall_clock_seconds"],
                "findings": [
                    finding_to_report_dict(f)
                    for f in partition_reportable(row.get("findings", []))[0]
                ],
                "confirmed_count": len(
                    partition_reportable(row.get("findings", []))[0]
                ),
                "suppressed_count": len(
                    partition_reportable(row.get("findings", []))[1]
                ),
            }
            for row in target_results
        ],
    }
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
    safe_markdown = render_stored_report_markdown(safe_json)
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
                )
            )
            if target_results[-1].get("timed_out"):
                console.print("[yellow]Stopping assessment after target timeout; review outstanding container work before retrying.[/]")
                break

    report_md, report_json = build_consolidated_report(
        engagement, targets, target_results
    )
    md_path, json_path = write_reports(report_md, report_json, args.out)
    console.print(f"[green bold]📄 Consolidated report:[/] {md_path}")
    console.print(f"[green]   📊 JSON:[/] {json_path}")
    return 0


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
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    from dotenv import load_dotenv

    from hacking_agent.core.paths import ENV_FILE
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)
    raise SystemExit(run_assessment(args))


if __name__ == "__main__":
    main()

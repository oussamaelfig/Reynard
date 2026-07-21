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
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from hacking_agent.agents.reporter import (
    Finding,
    extract_findings,
    render_assessment_report,
)
from hacking_agent.core.engagement import Engagement, EngagementError, load_engagement
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs

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
            "(authorized_domains / authorized_cidrs). Define an authorized "
            "scope before running an assessment."
        )

    denied = {d.strip().lower() for d in engagement.out_of_scope if d.strip()}

    def _is_denied(host: str) -> bool:
        host = (host or "").lower()
        return any(host == d or host.endswith(f".{d}") for d in denied)

    targets: list[str] = []
    if explicit:
        for raw in explicit:
            url = raw if "://" in raw else f"https://{raw}"
            host = (urlparse(url).hostname or "").lower()
            if _is_denied(host):
                console.print(f"[yellow]Skipping out-of-scope target: {raw}[/]")
                continue
            targets.append(url)
    else:
        for domain in engagement.authorized_domains:
            host = domain.strip().lower()
            if not host or _is_denied(host):
                continue
            targets.append(f"https://{host}/")

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
        "generated_at": datetime.utcnow().isoformat(),
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
) -> dict[str, Any]:
    """Run the Orchestrator against a single authorized target under the RoE.

    Returns a per-target result row including the extracted findings. Imports
    the orchestrator lazily so the offline scope/report logic stays importable
    without the full agent stack + optional runtime deps.
    """
    from hacking_agent.cli.orchestrator import Orchestrator

    console.print(f"[bold cyan]▶ Assessing target:[/] {target_url}")
    holder: dict[str, Any] = {}

    def _run() -> None:
        try:
            orch = Orchestrator(
                target_url=target_url,
                max_iterations=max_iterations,
                objective=(
                    "Authorized security assessment: recon, enumerate, and test "
                    "the in-scope target for exploitable vulnerabilities, then "
                    "produce evidence-backed findings."
                ),
                scope_domains=list(engagement.authorized_domains),
                scope_cidrs=list(engagement.authorized_cidrs),
            )
            # Install the rules of engagement onto the live ScopeGuard so every
            # tool call is gated by the out-of-scope denylist, rate limit,
            # request cap, and destructive-action policy.
            orch.scope_guard.attach_engagement(engagement)
            holder["orch"] = orch
            holder["result"] = orch.run()
        except Exception as exc:  # noqa: BLE001 - surfaced in verdict
            holder["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    started = time.time()
    thread.start()
    thread.join(per_target_timeout if per_target_timeout > 0 else None)
    elapsed = round(time.time() - started, 1)
    timed_out = thread.is_alive()

    orch = holder.get("orch")
    error = holder.get("error")
    findings: list[Finding] = []
    if orch is not None:
        try:
            findings = extract_findings(orch.memory, orch.evidence)
        except Exception:  # noqa: BLE001 - defensive snapshot
            findings = []

    if timed_out:
        verdict = f"timeout after {per_target_timeout}s"
    elif error is not None:
        verdict = f"error: {str(error)[:200]}"
    else:
        verdict = "assessed"

    return {
        "target": target_url,
        "verdict": verdict,
        "timed_out": timed_out,
        "wall_clock_seconds": elapsed,
        "findings": findings,
    }


def build_consolidated_report(
    engagement: Engagement,
    targets: list[str],
    target_results: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Aggregate per-target results into a consolidated report (md + json)."""
    meta = _engagement_meta(engagement, targets)
    all_findings: list[Finding] = []
    for row in target_results:
        all_findings.extend(row.get("findings", []))

    recon_summary_parts = [
        f"- `{row['target']}`: {row['verdict']} "
        f"({len(row.get('findings', []))} finding(s), {row['wall_clock_seconds']}s)"
        for row in target_results
    ]
    recon_summary = "\n".join(recon_summary_parts) or "No targets assessed."

    report_md = render_assessment_report(meta, all_findings, recon_summary)

    report_json = {
        **meta,
        "target_count": len(targets),
        "finding_count": len(all_findings),
        "verified_count": sum(1 for f in all_findings if f.verified),
        "targets_assessed": [
            {
                "target": row["target"],
                "verdict": row["verdict"],
                "wall_clock_seconds": row["wall_clock_seconds"],
                "findings": [
                    {
                        "title": f.title,
                        "vuln_type": f.vuln_type,
                        "severity": f.severity,
                        "cwe": f.cwe,
                        "cvss_vector": f.cvss_vector,
                        "cvss_score": f.cvss_score,
                        "endpoint": f.endpoint,
                        "parameter": f.parameter,
                        "verified": f.verified,
                    }
                    for f in row.get("findings", [])
                ],
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
    """Write the consolidated report to ``out_dir`` (default logs/)."""
    if out_dir:
        base = Path(out_dir)
        base.mkdir(parents=True, exist_ok=True)
    else:
        ensure_runtime_dirs()
        base = LOG_DIR
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    md_path = base / f"assessment_{ts}.md"
    json_path = base / f"assessment_{ts}.json"
    md_path.write_text(report_md, encoding="utf-8")
    json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
    return md_path, json_path


def run_assessment(args: argparse.Namespace) -> int:
    """Load the engagement, resolve targets, run each, and write the report."""
    try:
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
        required=True,
        help="Engagement config file (YAML or JSON). See eval/engagement.sample.yaml.",
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

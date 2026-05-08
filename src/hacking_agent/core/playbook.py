"""
=============================================================================
Hacking Agent — Playbook Engine (YAML-Driven Methodology)
=============================================================================
Loads methodology pipelines from YAML files, replacing the hardcoded
strategy.py phase definitions with pluggable, operator-customizable
playbooks.

Inspired by Pentest-Swarm-AI's playbooks/*.yaml pattern where each playbook
defines phases, tools, post-analysis prompts, and exit conditions.

Playbook format
───────────────
  name: XSS Exploitation Pipeline
  description: Phase-based XSS methodology for CTF labs
  tags: [xss, ctf, web]
  variables:
    target_url: { type: string, required: true }
  phases:
    - name: recon
      description: Identify injection points and technology stack
      max_attempts: 12
      tools: [http_request, browser_navigate]
      payloads:
        - payload: "teststring123"
          purpose: "Find reflection point"
      exit_conditions:
        - "injection_point is not None"
      instructions: |
        RECON PHASE — Your goal is reconnaissance. Do NOT exploit yet.

Usage
─────
  book = Playbook.load("playbooks/xss_pipeline.yaml")
  phase = book.get_phase("recon")
  prompt = book.get_phase_prompt("recon", known_facts={})
=============================================================================
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PlaybookPhase:
    """A single phase in a playbook pipeline."""
    name: str
    description: str = ""
    max_attempts: int = 10
    tools: list[str] = field(default_factory=list)
    payloads: list[dict[str, str]] = field(default_factory=list)
    entry_conditions: list[str] = field(default_factory=list)
    exit_conditions: list[str] = field(default_factory=list)
    instructions: str = ""
    post_analysis: str = ""


@dataclass
class PlaybookVariable:
    """A variable required or accepted by a playbook."""
    name: str
    type: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""


@dataclass
class Playbook:
    """A loaded playbook definition."""
    name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    version: str = "1.0.0"
    variables: list[PlaybookVariable] = field(default_factory=list)
    phases: list[PlaybookPhase] = field(default_factory=list)
    source_path: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Playbook":
        """Load a playbook from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Playbook must be a YAML mapping, got: {type(data)}")

        # Parse variables
        variables: list[PlaybookVariable] = []
        for var_name, var_def in (data.get("variables") or {}).items():
            if isinstance(var_def, dict):
                variables.append(PlaybookVariable(
                    name=var_name,
                    type=var_def.get("type", "string"),
                    required=var_def.get("required", False),
                    default=var_def.get("default"),
                    description=var_def.get("description", ""),
                ))
            else:
                variables.append(PlaybookVariable(name=var_name))

        # Parse phases
        phases: list[PlaybookPhase] = []
        for phase_data in data.get("phases") or []:
            phases.append(PlaybookPhase(
                name=phase_data.get("name", ""),
                description=phase_data.get("description", ""),
                max_attempts=phase_data.get("max_attempts", 10),
                tools=phase_data.get("tools") or [],
                payloads=phase_data.get("payloads") or [],
                entry_conditions=phase_data.get("entry_conditions") or [],
                exit_conditions=phase_data.get("exit_conditions") or [],
                instructions=phase_data.get("instructions", ""),
                post_analysis=phase_data.get("post_analysis", ""),
            ))

        return cls(
            name=data.get("name", path.stem),
            description=data.get("description", ""),
            tags=data.get("tags") or [],
            version=data.get("version", "1.0.0"),
            variables=variables,
            phases=phases,
            source_path=str(path),
        )

    # ---- phase access ----------------------------------------------------

    def get_phase(self, phase_name: str) -> PlaybookPhase | None:
        """Get a phase by name."""
        for phase in self.phases:
            if phase.name == phase_name:
                return phase
        return None

    def phase_names(self) -> list[str]:
        """Return ordered list of phase names."""
        return [p.name for p in self.phases]

    # ---- prompt generation -----------------------------------------------

    def get_phase_prompt(self, phase_name: str,
                          known_facts: dict[str, Any] | None = None,
                          attempt_count: int = 0) -> str:
        """Generate the full instruction prompt for a phase."""
        phase = self.get_phase(phase_name)
        if not phase:
            return f"Unknown phase: {phase_name}"

        lines = [
            f"{'='*60}",
            f"CURRENT PHASE: {phase.name.upper()}",
            f"{'='*60}",
            f"Goal: {phase.description}",
            "",
        ]

        if phase.exit_conditions:
            lines.append("Exit conditions (ALL must be met to advance):")
            for cond in phase.exit_conditions:
                lines.append(f"  - {cond}")

        lines.append(f"\nAttempts: {attempt_count}/{phase.max_attempts}")

        if phase.tools:
            lines.append(f"\nAllowed tools: {', '.join(phase.tools)}")

        if phase.instructions:
            lines.append(f"\n{phase.instructions}")

        if phase.payloads:
            lines.append(f"\nSuggested payloads for this phase:")
            for i, p in enumerate(phase.payloads, 1):
                lines.append(f"  {i}. {p.get('payload', '')}")
                if p.get("purpose"):
                    lines.append(f"     Purpose: {p['purpose']}")

        if phase.post_analysis:
            lines.append(f"\nPost-analysis guidance:\n{phase.post_analysis}")

        return "\n".join(lines)

    # ---- validation ------------------------------------------------------

    def validate_variables(self, provided: dict[str, Any]) -> list[str]:
        """Check that all required variables are provided. Returns errors."""
        errors: list[str] = []
        for var in self.variables:
            if var.required and var.name not in provided:
                errors.append(f"Required variable '{var.name}' not provided")
        return errors

    def describe(self) -> str:
        """Human-readable summary."""
        phases_str = " → ".join(p.name.upper() for p in self.phases)
        return (
            f"Playbook: {self.name} v{self.version}\n"
            f"  {self.description}\n"
            f"  Phases: {phases_str}\n"
            f"  Tags: {', '.join(self.tags)}"
        )


# =============================================================================
# Playbook discovery
# =============================================================================

def discover_playbooks(playbook_dir: str | Path | None = None) -> dict[str, Playbook]:
    """Find and load all playbooks in a directory.

    Returns a dict keyed by playbook name.
    """
    if playbook_dir is None:
        playbook_dir = Path(__file__).parent / "playbooks"
    else:
        playbook_dir = Path(playbook_dir)

    if not playbook_dir.is_dir():
        return {}

    books: dict[str, Playbook] = {}
    for yaml_file in sorted(playbook_dir.glob("*.yaml")):
        try:
            book = Playbook.load(yaml_file)
            books[book.name] = book
        except Exception as e:
            # Log but don't crash — one bad playbook shouldn't block the rest
            print(f"Warning: failed to load playbook {yaml_file}: {e}")

    for yml_file in sorted(playbook_dir.glob("*.yml")):
        try:
            book = Playbook.load(yml_file)
            if book.name not in books:
                books[book.name] = book
        except Exception:
            pass

    return books

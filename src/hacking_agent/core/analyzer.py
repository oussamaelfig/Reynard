"""
=============================================================================
Reynard — Response Analyzer
=============================================================================
Transforms raw HTTP responses (headers + body) into structured JSON signals.

Instead of forcing DeepSeek to mentally parse raw HTML every time, this
module extracts key security-relevant signals automatically:
  - Reflection detection (is our input echoed back?)
  - Encoding detection (HTML-encoded, URL-encoded, or raw?)
  - Context detection (HTML body, attribute, JS string, Angular template?)
  - AngularJS detection (ng-app, angular.js, template evaluation?)
  - CSP header parsing
  - Error/WAF detection

Output is a structured JSON dict injected into the conversation.
=============================================================================
"""

import re
import json
from typing import Any
from urllib.parse import unquote


# =============================================================================
# ResponseAnalyzer
# =============================================================================

class ResponseAnalyzer:
    """
    Analyzes raw HTTP responses and extracts structured security signals.
    """

    # Common AngularJS indicators
    ANGULAR_PATTERNS = [
        r'ng-app',
        r'angular\.js',
        r'angular\.min\.js',
        r'ng-controller',
        r'ng-model',
        r'ng-bind',
        r'\{\{.*?\}\}',  # Angular template expressions
    ]

    # Common WAF/error patterns
    WAF_PATTERNS = [
        r'access denied',
        r'blocked',
        r'403 forbidden',
        r'web application firewall',
        r'cloudflare',
        r'mod_security',
        r'request blocked',
        r'invalid request',
    ]

    # HTML encoding map
    HTML_ENTITIES = {
        '&lt;': '<',
        '&gt;': '>',
        '&amp;': '&',
        '&quot;': '"',
        '&#x27;': "'",
        '&#39;': "'",
        '&apos;': "'",
    }

    def analyze(
        self,
        response_text: str,
        payload: str = "",
        url: str = "",
    ) -> dict[str, Any]:
        """
        Analyze an HTTP response and extract structured signals.

        Args:
            response_text: Raw HTTP response (headers + body or just body)
            payload: The payload that was sent (for reflection detection)
            url: The URL that was requested

        Returns:
            Structured signals as a dict
        """
        # Split headers and body if possible
        headers_text, body = self._split_headers_body(response_text)

        signals = {
            # --- Reflection ---
            "reflected": False,
            "reflection_count": 0,
            "reflection_context": None,  # "html_body", "html_attribute", "js_string", "js_code", "comment", "angular_template"
            "reflection_raw": False,     # Reflected without encoding
            "reflection_encoded": False, # Reflected but HTML-encoded

            # --- Encoding ---
            "html_encoded": False,
            "url_encoded": False,
            "encoding_details": [],

            # --- AngularJS ---
            "angular_detected": False,
            "angular_version": None,
            "angular_evaluated": False,  # Did {{7*7}} become 49?
            "ng_app_present": False,

            # --- JavaScript Context ---
            "javascript_context": False,
            "script_tags_present": False,
            "inline_js_handlers": False,

            # --- Security Headers ---
            "status_code": None,
            "content_type": None,
            "csp_header": None,
            "x_frame_options": None,

            # --- Errors/WAF ---
            "error_detected": False,
            "error_message": None,
            "waf_detected": False,

            # --- Content Analysis ---
            "forms_detected": 0,
            "input_fields": [],
            "interesting_patterns": [],

            # --- Lab-specific ---
            "lab_solved": False,
            "payload_executed": False,
        }

        # Run all analyzers
        self._analyze_status(headers_text, signals)
        self._analyze_security_headers(headers_text, signals)
        self._analyze_reflection(body, payload, signals)
        self._analyze_angular(body, signals)
        self._analyze_javascript(body, signals)
        self._analyze_forms(body, signals)
        self._analyze_errors(body, signals)
        self._check_lab_solved(body, signals)

        return signals

    # -----------------------------------------------------------------
    # Internal Analyzers
    # -----------------------------------------------------------------

    def _split_headers_body(self, response: str) -> tuple[str, str]:
        """Split response into headers and body."""
        # Look for the standard HTTP header/body separator
        separators = ['\r\n\r\n', '\n\n']
        for sep in separators:
            if sep in response:
                idx = response.index(sep)
                # Only treat as headers if first line looks like HTTP status
                first_line = response[:idx].split('\n')[0]
                if first_line.startswith('HTTP/') or ':' in first_line:
                    return response[:idx], response[idx + len(sep):]
        return "", response

    def _analyze_status(self, headers: str, signals: dict) -> None:
        """Extract HTTP status code."""
        match = re.search(r'HTTP/[\d.]+ (\d+)', headers)
        if match:
            signals["status_code"] = int(match.group(1))

    def _analyze_security_headers(self, headers: str, signals: dict) -> None:
        """Extract security-relevant headers."""
        headers_lower = headers.lower()

        # Content-Type
        match = re.search(r'content-type:\s*([^\r\n]+)', headers_lower)
        if match:
            signals["content_type"] = match.group(1).strip()

        # CSP
        match = re.search(r'content-security-policy:\s*([^\r\n]+)', headers_lower)
        if match:
            signals["csp_header"] = match.group(1).strip()

        # X-Frame-Options
        match = re.search(r'x-frame-options:\s*([^\r\n]+)', headers_lower)
        if match:
            signals["x_frame_options"] = match.group(1).strip()

    def _analyze_reflection(self, body: str, payload: str, signals: dict) -> None:
        """Check if the payload is reflected in the response and how."""
        if not payload or not body:
            return

        # Check raw reflection (exact match)
        if payload in body:
            signals["reflected"] = True
            signals["reflection_raw"] = True
            signals["reflection_count"] = body.count(payload)
            signals["reflection_context"] = self._detect_context(body, payload)

        # Check HTML-encoded reflection
        encoded_payload = (
            payload
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;')
        )
        if encoded_payload in body and encoded_payload != payload:
            signals["reflected"] = True
            signals["reflection_encoded"] = True
            signals["html_encoded"] = True
            signals["encoding_details"].append("html_entity_encoded")
            if not signals["reflection_context"]:
                signals["reflection_context"] = self._detect_context(body, encoded_payload)

        # Check partial encoding (only < and > encoded)
        partial_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if partial_encoded in body and partial_encoded != payload and partial_encoded != encoded_payload:
            signals["reflected"] = True
            signals["reflection_encoded"] = True
            signals["encoding_details"].append("angle_brackets_encoded")

        # Check for Angular template evaluation
        if '{{' in payload and '}}' in payload:
            # Extract the expression
            expr_match = re.search(r'\{\{(.+?)\}\}', payload)
            if expr_match:
                expr = expr_match.group(1)
                # Check if it was evaluated (e.g., {{7*7}} became 49)
                try:
                    expected = str(eval(expr))  # Safe for simple math
                    if expected in body and '{{' not in body.split(expected)[0][-10:]:
                        signals["angular_evaluated"] = True
                        signals["reflected"] = True
                        signals["reflection_context"] = "angular_template"
                except Exception:
                    pass

    def _detect_context(self, body: str, payload: str) -> str:
        """Determine the HTML context where the payload appears."""
        idx = body.find(payload)
        if idx == -1:
            return "unknown"

        # Get surrounding context (200 chars before and after)
        before = body[max(0, idx - 200):idx]
        after = body[idx + len(payload):idx + len(payload) + 200]

        # Check if inside a <script> tag
        last_script_open = before.rfind('<script')
        last_script_close = before.rfind('</script')
        if last_script_open > last_script_close:
            # Check if inside a JS string
            # Count unescaped quotes before the payload
            js_before = before[last_script_open:]
            single_quotes = js_before.count("'") - js_before.count("\\'")
            double_quotes = js_before.count('"') - js_before.count('\\"')
            if single_quotes % 2 == 1 or double_quotes % 2 == 1:
                return "js_string"
            return "js_code"

        # Check if inside an HTML comment
        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close:
            return "html_comment"

        # Check if inside an HTML attribute
        # Look for pattern: attribute="...PAYLOAD..."
        attr_match = re.search(r'(\w+)\s*=\s*["\'][^"\']*$', before)
        if attr_match:
            return f"html_attribute:{attr_match.group(1)}"

        # Check if inside a tag (but not attribute)
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open > last_tag_close:
            return "html_tag"

        # Default: HTML body
        return "html_body"

    def _analyze_angular(self, body: str, signals: dict) -> None:
        """Detect AngularJS presence and configuration."""
        body_lower = body.lower()

        # Check for ng-app
        if 'ng-app' in body_lower:
            signals["ng_app_present"] = True
            signals["angular_detected"] = True

        # Check for angular.js script
        if 'angular' in body_lower and ('.js' in body_lower or 'angular.min' in body_lower):
            signals["angular_detected"] = True

        # Try to extract Angular version
        version_match = re.search(
            r'angular[^"\']*?(\d+\.\d+\.\d+)',
            body_lower
        )
        if version_match:
            signals["angular_version"] = version_match.group(1)
            signals["angular_detected"] = True

        # Check for template expressions in the page
        template_matches = re.findall(r'\{\{(.+?)\}\}', body)
        if template_matches:
            signals["interesting_patterns"].append(
                f"Angular expressions found: {template_matches[:3]}"
            )

    def _analyze_javascript(self, body: str, signals: dict) -> None:
        """Detect JavaScript contexts."""
        # Script tags
        script_count = len(re.findall(r'<script', body, re.IGNORECASE))
        if script_count > 0:
            signals["script_tags_present"] = True

        # Inline event handlers
        handler_patterns = re.findall(
            r'on\w+\s*=\s*["\']', body, re.IGNORECASE
        )
        if handler_patterns:
            signals["inline_js_handlers"] = True
            signals["interesting_patterns"].append(
                f"Event handlers: {len(handler_patterns)} found"
            )

    def _analyze_forms(self, body: str, signals: dict) -> None:
        """Detect forms and input fields."""
        forms = re.findall(r'<form[^>]*>', body, re.IGNORECASE)
        signals["forms_detected"] = len(forms)

        # Extract input fields
        inputs = re.findall(
            r'<input[^>]*?(?:name|id)\s*=\s*["\']([^"\']+)["\'][^>]*>',
            body, re.IGNORECASE
        )
        signals["input_fields"] = inputs[:10]  # Limit to 10

    def _analyze_errors(self, body: str, signals: dict) -> None:
        """Detect error messages and WAF blocks."""
        body_lower = body.lower()

        # WAF detection
        for pattern in self.WAF_PATTERNS:
            if re.search(pattern, body_lower):
                signals["waf_detected"] = True
                signals["error_detected"] = True
                match = re.search(pattern, body_lower)
                if match:
                    signals["error_message"] = match.group(0)
                break

        # Server error detection
        if signals.get("status_code") and signals["status_code"] >= 400:
            signals["error_detected"] = True

    def _check_lab_solved(self, body: str, signals: dict) -> None:
        """Check if the lab has been solved (PortSwigger specific)."""
        solved_indicators = [
            'congratulations',
            'you solved the lab',
            'lab solved',
            'solved!',
        ]
        body_lower = body.lower()
        for indicator in solved_indicators:
            if indicator in body_lower:
                signals["lab_solved"] = True
                signals["payload_executed"] = True
                break

    # -----------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------

    def format_signals(self, signals: dict) -> str:
        """Format signals as a readable string for the agent."""
        # Only include non-default/interesting signals
        interesting = {}
        defaults = {
            "reflected": False,
            "reflection_count": 0,
            "reflection_context": None,
            "reflection_raw": False,
            "reflection_encoded": False,
            "html_encoded": False,
            "url_encoded": False,
            "encoding_details": [],
            "angular_detected": False,
            "angular_version": None,
            "angular_evaluated": False,
            "ng_app_present": False,
            "javascript_context": False,
            "script_tags_present": False,
            "inline_js_handlers": False,
            "status_code": None,
            "content_type": None,
            "csp_header": None,
            "x_frame_options": None,
            "error_detected": False,
            "error_message": None,
            "waf_detected": False,
            "forms_detected": 0,
            "input_fields": [],
            "interesting_patterns": [],
            "lab_solved": False,
            "payload_executed": False,
        }

        for key, value in signals.items():
            if value != defaults.get(key):
                interesting[key] = value

        return json.dumps(interesting, indent=2)

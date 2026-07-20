"""Expert lab playbooks for authorized CTF and training targets.

These are deterministic priors, not proof. They help the agents avoid broad
generic recon when the user objective clearly names a PortSwigger-style lab
class. Every claim still has to be confirmed by target observations and the
EvidenceStore.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


Playbook = dict[str, Any]


EXPERT_PLAYBOOKS: dict[str, Playbook] = {
    "oauth_ssrf_dynamic_registration": {
        "id": "oauth_ssrf_dynamic_registration",
        "vulnerability": "OAuth/OIDC SSRF via dynamic client registration",
        "primary_tools": ["http_request", "caido_local_api", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Fetch /.well-known/openid-configuration and identify the registration endpoint.",
            "Confirm whether client metadata fields are fetched by the OAuth service.",
            "Capture a normal login flow only if credentials are provided or required.",
        ],
        "required_artifacts": [
            "OIDC discovery response",
            "client registration request/response",
            "metadata-fetch evidence or disclosed metadata response",
            "final lab-solved signal or secret value",
        ],
        "exploit_strategy": [
            "Register a client with metadata URLs pointing to a controlled URL first.",
            "If callback is confirmed, switch the metadata URL to the lab-intended internal metadata path.",
            "Use Caido Replay/history for raw request adjustment and durable artifacts.",
        ],
        "validation": [
            "Registration succeeds with attacker-controlled metadata.",
            "OAuth service performs the server-side fetch.",
            "Response or lab banner reveals the expected metadata/secret.",
        ],
        "pivot_hints": [
            "If direct internal URL is blocked, test redirect chains from an in-scope URL.",
            "If no callback arrives, verify the exact JSON field name accepted by the registration endpoint.",
            "If auth is needed, login with supplied lab credentials before starting the OAuth flow.",
        ],
        "avoid": [
            "Do not scan unrelated academy hosts.",
            "Do not treat 169.254.169.254 as an out-of-scope direct shell target; it is only an SSRF payload destination.",
        ],
    },
    "ssrf": {
        "id": "ssrf",
        "vulnerability": "Server-side request forgery",
        "primary_tools": ["http_request", "caido_local_api", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Find URL, stock-check, webhook, image-fetch, import, or link-preview parameters.",
            "Identify whether the fetcher returns in-band content or only blind callbacks.",
            "Record host allowlist, URL parser, and redirect behavior.",
        ],
        "required_artifacts": [
            "Baseline request to the URL-consuming endpoint",
            "OOB callback or in-band response from a controlled URL",
            "bypass payload and final impact response",
        ],
        "exploit_strategy": [
            "Start with a controlled URL and OOB callback to prove server-side fetch.",
            "Probe parser bypasses only after the basic fetch primitive is confirmed.",
            "Use differential responses to separate blocked, fetched, and cached states.",
        ],
        "validation": [
            "A server-side fetch reaches the controlled endpoint.",
            "Changing the payload changes the observed callback or response.",
            "The final payload reaches the lab-required internal resource.",
        ],
        "pivot_hints": [
            "Try redirects, mixed-case hosts, encoded dots, IPv6/decimal IP forms, or userinfo only when allowlist behavior is observed.",
            "If no in-band output exists, switch to OOB immediately.",
        ],
        "avoid": ["Do not directly scan internal IPs from the agent host."],
    },
    "blind_xxe_oob": {
        "id": "blind_xxe_oob",
        "vulnerability": "Blind XXE with out-of-band interaction",
        "primary_tools": ["http_request", "caido_local_api", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Find XML endpoints and confirm Content-Type requirements.",
            "Capture one valid baseline XML body before injecting a DOCTYPE.",
            "Confirm whether the parser blocks external entities or only in-band output.",
        ],
        "required_artifacts": [
            "valid baseline XML request",
            "DOCTYPE payload containing controlled OOB domain",
            "OOB interaction log",
        ],
        "exploit_strategy": [
            "Preserve the original XML structure and add a minimal external entity.",
            "Use a fresh OOB domain per attempt to avoid stale callback confusion.",
            "Poll OOB after each request before changing payload shape.",
        ],
        "validation": [
            "Any DNS or HTTP interaction from the target confirms blind XXE.",
            "A control request without the external entity produces no matching callback.",
        ],
        "pivot_hints": [
            "If a DOCTYPE is rejected, try parameter entities or external DTD form.",
            "If Content-Type is enforced, send exactly application/xml or the observed type.",
        ],
        "avoid": ["Do not claim success from a 200 response alone."],
    },
    "os_command_injection": {
        "id": "os_command_injection",
        "vulnerability": "OS command injection",
        "primary_tools": ["http_request", "run_shell", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Find parameters used by stock checks, diagnostics, file converters, or ping/traceroute features.",
            "Capture baseline output, timing, and status for a benign value.",
            "Identify likely OS from headers, errors, and command output.",
        ],
        "required_artifacts": [
            "baseline request",
            "payload request",
            "in-band command output, timing delta, or OOB callback",
        ],
        "exploit_strategy": [
            "Try the smallest separator payload that preserves the original parameter.",
            "Use time-based probes when output is hidden.",
            "Use OOB DNS/HTTP when timing is noisy or blocked.",
        ],
        "validation": [
            "whoami/id/hostname output appears in-band, or",
            "sleep delay is at least four seconds above baseline, or",
            "OOB callback is tied to the command payload.",
        ],
        "pivot_hints": [
            "Switch separators between ;, &, &&, |, ||, newline, and URL-encoded variants.",
            "If Linux commands fail, try Windows-safe probes before abandoning.",
        ],
        "avoid": ["Do not run destructive commands."],
    },
    "sqli": {
        "id": "sqli",
        "vulnerability": "SQL injection",
        "primary_tools": ["http_request", "run_shell", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Identify injectable parameters in query strings, forms, cookies, and JSON bodies.",
            "Capture true/false or baseline/error responses for each candidate.",
            "Record DB-specific error messages and comment syntax hints.",
        ],
        "required_artifacts": [
            "baseline request",
            "boolean/error/time payload request",
            "response diff or extracted data proving impact",
        ],
        "exploit_strategy": [
            "Use targeted manual probes for simple academy labs.",
            "Escalate to sqlmap after two focused probes fail or extraction is non-trivial.",
            "Prefer differential comparison for hidden-data and boolean-blind labs.",
        ],
        "validation": [
            "Payload causally changes returned rows, errors, or timing.",
            "Control payload restores the baseline behavior.",
            "Lab solved banner or required data is observed.",
        ],
        "pivot_hints": [
            "Try alternate comment styles, quote types, URL encoding, and body/cookie locations.",
            "For blind labs, switch from in-band to boolean, time, then OOB as needed.",
        ],
        "avoid": ["Do not run sqlmap against a whole domain when one parameter is known."],
    },
    "nosql_injection": {
        "id": "nosql_injection",
        "vulnerability": "NoSQL injection",
        "primary_tools": ["http_request", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Find JSON login/search/filter endpoints and observe backend error shapes.",
            "Confirm whether operators are accepted as JSON objects or strings.",
            "Capture failed and successful authentication/search baselines where possible.",
        ],
        "required_artifacts": [
            "baseline JSON request",
            "operator or syntax probe",
            "differential response showing bypass or data expansion",
        ],
        "exploit_strategy": [
            "Test syntax-breaking probes first, then operator injection.",
            "For auth bypass labs, compare wrong password with operator-based password condition.",
            "Use response length, status, redirects, and account page content as signals.",
        ],
        "validation": [
            "Injected condition changes auth/search behavior compared with controls.",
            "The resulting page shows the target account, data set, or solved banner.",
        ],
        "pivot_hints": [
            "Try both JSON operators and string syntax when content type differs.",
            "If filters reject objects, test regex or where-like syntax in strings.",
        ],
        "avoid": ["Do not brute force credentials when a logic/operator proof is available."],
    },
    "jwt": {
        "id": "jwt",
        "vulnerability": "JWT authentication flaw",
        "primary_tools": ["http_request", "run_shell", "browser_navigate"],
        "recon_goals": [
            "Extract JWTs from cookies, Authorization headers, storage, or JS.",
            "Decode header/payload and identify alg, kid, jku, jwk, iss, aud, and role claims.",
            "Find role-gated endpoints and admin-only actions.",
        ],
        "required_artifacts": [
            "original token header/payload",
            "modified token or key-confusion setup",
            "admin-only response or solved banner",
        ],
        "exploit_strategy": [
            "Check for alg=none, weak HMAC secret, kid path traversal, embedded jwk, and jku/jwks trust issues.",
            "Only modify the claim needed for the lab goal, usually role/sub/username.",
            "Replay the exact privileged request with the modified token.",
        ],
        "validation": [
            "Privileged endpoint accepts the altered token.",
            "A control token with invalid signature or unchanged claims fails.",
        ],
        "pivot_hints": [
            "If alg=none fails, test weak secret or key confusion based on header fields.",
            "If kid is present, look for path traversal or SQLi into key lookup.",
        ],
        "avoid": ["Do not assume base64 decoding equals vulnerability."],
    },
    "access_control_idor": {
        "id": "access_control_idor",
        "vulnerability": "Broken access control / IDOR",
        "primary_tools": ["http_request", "list_sessions", "swap_session", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Find object identifiers in URLs, JSON bodies, forms, and JS routes.",
            "Map at least two identities when credentials/sessions are available.",
            "Identify admin-only, owner-only, or tenant-scoped endpoints.",
        ],
        "required_artifacts": [
            "victim/object baseline",
            "attacker request with swapped identifier or session",
            "response proving unauthorized access or state change",
        ],
        "exploit_strategy": [
            "Compare the same endpoint under user1, user2, and unauthenticated sessions.",
            "Change only one identifier at a time to preserve causal proof.",
            "For method-based bypasses, replay GET/POST/PUT/PATCH variants with identical path.",
        ],
        "validation": [
            "Attacker session accesses or modifies another user's object.",
            "Control request to an unrelated object or unauthenticated session fails.",
        ],
        "pivot_hints": [
            "Try numeric, UUID, username, email, and hidden form identifiers.",
            "Check Referer/Host/X-Original-URL/X-Rewrite-URL override patterns for access control labs.",
        ],
        "avoid": ["Do not mark IDOR verified without a cross-session comparison when sessions exist."],
    },
    "request_smuggling": {
        "id": "request_smuggling",
        "vulnerability": "HTTP request smuggling / desync",
        "primary_tools": ["request_smuggling_probe", "run_shell", "http_request", "caido_local_api"],
        "recon_goals": [
            "Identify front-end/back-end clues, HTTP/1.1 support, and proxy/cache headers.",
            "Capture stable baseline timings and response queue behavior.",
            "Determine whether CL.TE, TE.CL, or HTTP/2 downgrade vectors are plausible.",
        ],
        "required_artifacts": [
            "raw baseline request",
            "smuggling probe request with exact headers/body length",
            "timeout, queue poisoning, reflected prefix, or victim-impact evidence",
        ],
        "exploit_strategy": [
            "Use request_smuggling_probe, raw sockets, or Caido Replay; standard HTTP clients often normalize away the bug.",
            "Start with safe timeout probes before attempting response-queue poisoning.",
            "Keep exact Content-Length and Transfer-Encoding evidence in the PoC.",
        ],
        "validation": [
            "A control request is stable while a crafted desync probe causes timeout or queued response.",
            "The exploit reaches the lab-required endpoint or poisons the intended request only.",
        ],
        "pivot_hints": [
            "Try CL.TE, TE.CL, TE obfuscation, and HTTP/2 downgrade variants based on observed support.",
            "If proxies normalize, use Caido raw request sending or a custom socket script.",
        ],
        "avoid": ["Do not rely on browser requests for the core smuggling proof."],
    },
    "web_cache_poisoning": {
        "id": "web_cache_poisoning",
        "vulnerability": "Web cache poisoning/deception",
        "primary_tools": ["http_request", "caido_local_api", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Identify cacheable responses and cache keys via headers and repeat requests.",
            "Find unkeyed inputs: Host, X-Forwarded-Host, X-Original-URL, query params, cookies, or headers.",
            "Determine cache buster requirements and TTL behavior.",
        ],
        "required_artifacts": [
            "cacheable baseline response",
            "poisoning request",
            "follow-up victim-equivalent request receiving poisoned content",
        ],
        "exploit_strategy": [
            "Use a cache buster while testing, then remove or align it for final impact.",
            "Change one suspected unkeyed input per request.",
            "Confirm poisoning by fetching the same cache key without the malicious input.",
        ],
        "validation": [
            "The malicious value appears in a cached follow-up response.",
            "A different cache key remains clean.",
        ],
        "pivot_hints": [
            "If headers fail, test path normalization, query exclusion, and static extension deception.",
            "If nothing caches, look for CDN/proxy-specific headers or labs requiring a particular path.",
        ],
        "avoid": ["Do not poison broad shared cache keys outside the authorized lab."],
    },
    "ssti": {
        "id": "ssti",
        "vulnerability": "Server-side template injection",
        "primary_tools": ["http_request", "run_shell", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Find reflected parameters in names, messages, emails, templates, and error pages.",
            "Fingerprint template syntax with arithmetic probes.",
            "Identify engine clues from errors, framework headers, or response syntax.",
        ],
        "required_artifacts": [
            "baseline reflection",
            "arithmetic or engine-specific probe",
            "executed expression output or safe command proof",
        ],
        "exploit_strategy": [
            "Start with harmless arithmetic expressions across likely syntaxes.",
            "Fingerprint the engine before using engine-specific payloads.",
            "Escalate to safe file read or command proof only when the lab requires impact.",
        ],
        "validation": [
            "Expression output is evaluated server-side, not reflected literally.",
            "Control expression stays literal or produces different expected output.",
        ],
        "pivot_hints": [
            "Try URL/body/header contexts and HTML/attribute escaped contexts.",
            "If output is hidden, use time or OOB callbacks from engine features.",
        ],
        "avoid": ["Do not skip engine fingerprinting after one arithmetic hit."],
    },
    "deserialization": {
        "id": "deserialization",
        "vulnerability": "Insecure deserialization",
        "primary_tools": ["http_request", "run_shell", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Find cookies, hidden fields, or API values that look serialized, signed, or base64 encoded.",
            "Identify language/framework markers in data and errors.",
            "Determine whether integrity signing exists and whether secrets are discoverable.",
        ],
        "required_artifacts": [
            "original serialized value",
            "decoded/modified value or gadget payload",
            "in-band, timing, or OOB proof of deserialization impact",
        ],
        "exploit_strategy": [
            "Decode and minimally modify a non-dangerous field first.",
            "Identify signing/encryption before attempting gadget chains.",
            "Use OOB/timing proof for blind gadget execution.",
        ],
        "validation": [
            "Modified serialized data changes server behavior.",
            "Final payload produces lab-required impact and a control value does not.",
        ],
        "pivot_hints": [
            "If signing blocks tampering, search observed source/JS/leaks for keys.",
            "Try language-specific magic bytes and formats only after identifying the stack.",
        ],
        "avoid": ["Do not generate destructive gadget payloads."],
    },
    "prototype_pollution": {
        "id": "prototype_pollution",
        "vulnerability": "Prototype pollution",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js", "caido_local_api"],
        "recon_goals": [
            "Find JSON merge points, querystring parsers, and client-side object assignment sinks.",
            "Identify whether pollution is client-side, server-side, or both.",
            "Locate an impact gadget such as DOM XSS, config override, or privilege flag.",
        ],
        "required_artifacts": [
            "pollution source request/input",
            "observable polluted property",
            "impact gadget response or DOM state",
        ],
        "exploit_strategy": [
            "Probe __proto__, constructor.prototype, and nested JSON forms with harmless properties.",
            "For client-side labs, verify in the browser JS context before chasing impact.",
            "For server-side labs, use differential requests and response changes.",
        ],
        "validation": [
            "A polluted property becomes visible in object lookups or behavior.",
            "A separate impact gadget consumes the polluted property.",
        ],
        "pivot_hints": [
            "Switch between URL-encoded, JSON, and dotted/bracket notation.",
            "If source works but no impact, enumerate gadgets in JS bundles.",
        ],
        "avoid": ["Do not call pollution impact proven from source-only evidence."],
    },
    "graphql_api": {
        "id": "graphql_api",
        "vulnerability": "GraphQL API weakness",
        "primary_tools": ["http_request", "run_shell", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Discover GraphQL endpoint and whether introspection is enabled.",
            "List queries, mutations, object types, and auth-sensitive fields.",
            "Identify IDOR, authz, batching, aliasing, or hidden mutation opportunities.",
        ],
        "required_artifacts": [
            "schema/introspection or inferred operation",
            "baseline authorized/unauthorized query",
            "query or mutation proving unauthorized access or state change",
        ],
        "exploit_strategy": [
            "Use introspection when enabled; otherwise infer from JS and errors.",
            "Test object-level authorization with swapped IDs under different sessions.",
            "Use aliases/batching only when rate limits or workflow checks are relevant to the lab.",
        ],
        "validation": [
            "Unauthorized session reads or mutates data it should not access.",
            "Control query under the correct session boundary behaves differently.",
        ],
        "pivot_hints": [
            "Try GET vs POST, content-type variants, and operationName mismatches.",
            "If introspection is blocked, mine frontend JS for queries and fragments.",
        ],
        "avoid": ["Do not flood with broad wordlists before parsing JS operations."],
    },
    "race_condition": {
        "id": "race_condition",
        "vulnerability": "Race condition",
        "primary_tools": ["run_shell", "http_request", "caido_local_api"],
        "recon_goals": [
            "Find single-use actions: coupon redemption, password reset, email change, purchase, or transfer.",
            "Capture the exact state-changing request and required session tokens.",
            "Measure normal sequential behavior before parallel replay.",
        ],
        "required_artifacts": [
            "state-changing baseline request",
            "parallel replay script or Caido sequence",
            "post-race state showing duplicate effect or bypass",
        ],
        "exploit_strategy": [
            "Send synchronized identical requests against one state transition.",
            "Keep CSRF/session tokens constant only when the app accepts one-use race windows.",
            "Verify final state through the UI/API after the parallel burst.",
        ],
        "validation": [
            "The final account/order/resource state shows more than one accepted transition.",
            "Sequential control attempts do not produce the same result.",
        ],
        "pivot_hints": [
            "Increase concurrency, reduce network jitter, and use HTTP/2 single-packet style where supported.",
            "Try last-byte synchronization for labs with strict timing.",
        ],
        "avoid": ["Do not repeat state-changing races without checking lab state between runs."],
    },
    "xss": {
        "id": "xss",
        "vulnerability": "Cross-site scripting",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Find reflected, stored, and client-rendered input locations.",
            "Determine exact context: HTML body, attribute, JavaScript string, URL, template, or markdown.",
            "Identify filters, encoders, CSP, and required victim workflow.",
        ],
        "required_artifacts": [
            "baseline reflection/storage request",
            "context-appropriate payload",
            "browser-observed execution or lab-solved signal",
        ],
        "exploit_strategy": [
            "Map context before choosing payload syntax.",
            "Use browser tools to prove execution, not just reflection.",
            "For stored XSS, verify the victim-visible page or lab delivery path.",
        ],
        "validation": [
            "Attacker-controlled JavaScript executes in the browser context.",
            "A control payload is reflected/stored without execution or is escaped.",
            "CSP and sanitizer behavior are accounted for in the proof.",
        ],
        "pivot_hints": [
            "Switch contexts: HTML, attribute, script string, URL handler, SVG, markdown, and template.",
            "If reflected XSS is blocked, mine JS for DOM sinks or stored rendering paths.",
        ],
        "avoid": ["Do not treat reflected markup as JavaScript execution without browser proof."],
    },
    "dom_xss": {
        "id": "dom_xss",
        "vulnerability": "DOM-based XSS",
        "primary_tools": ["browser_navigate", "browser_execute_js", "http_request"],
        "recon_goals": [
            "Find sources: location, hash, search, postMessage, storage, document.referrer.",
            "Find sinks in JS bundles: innerHTML, document.write, eval, setTimeout string, template renderers.",
            "Determine escaping and execution context.",
        ],
        "required_artifacts": [
            "source-to-sink trace",
            "payload URL or message",
            "browser-observed execution signal",
        ],
        "exploit_strategy": [
            "Use browser execution to verify DOM changes and script execution.",
            "Choose payload syntax for the actual sink context.",
            "For postMessage labs, send a controlled message from a same-browser page/script.",
        ],
        "validation": [
            "The browser executes attacker-controlled JavaScript.",
            "A control value reaches the sink without execution or is escaped.",
        ],
        "pivot_hints": [
            "If reflection is escaped in HTML, test attribute, JS string, URL, and template-literal contexts.",
            "If source is postMessage, inspect origin checks and required message shape.",
        ],
        "avoid": ["Do not treat reflected text in HTML as executed XSS."],
    },
    "file_upload": {
        "id": "file_upload",
        "vulnerability": "File upload bypass",
        "primary_tools": ["http_request", "run_shell", "browser_navigate"],
        "recon_goals": [
            "Map upload endpoint, retrieval path, extension/content-type checks, and image processing.",
            "Capture successful benign upload and resulting file URL.",
            "Identify server language and executable upload locations.",
        ],
        "required_artifacts": [
            "benign upload request/response",
            "bypass upload request",
            "retrieval/execution response proving impact",
        ],
        "exploit_strategy": [
            "Change one control at a time: extension, Content-Type, magic bytes, filename path, or polyglot body.",
            "If execution is impossible, look for path traversal overwrite or stored XSS impact.",
            "Use the returned retrieval path as the validation target.",
        ],
        "validation": [
            "The uploaded file is retrievable and interpreted in the dangerous context required by the lab.",
            "Benign/control upload does not produce the same impact.",
        ],
        "pivot_hints": [
            "Try double extensions, null-byte style only if stack indicates legacy behavior, and content-type/magic-byte mismatches.",
            "If images are reprocessed, test metadata or polyglot strategies.",
        ],
        "avoid": ["Do not upload destructive web shells outside lab scope."],
    },
    "path_traversal": {
        "id": "path_traversal",
        "vulnerability": "Path traversal / file path manipulation",
        "primary_tools": ["http_request", "caido_local_api", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Find filename, image, download, template, include, or static asset parameters.",
            "Capture normal file retrieval and error behavior.",
            "Identify normalization, base directory, and encoding filters.",
        ],
        "required_artifacts": [
            "baseline file request",
            "traversal payload request",
            "target file content or lab-solved signal",
        ],
        "exploit_strategy": [
            "Start with the lab-required file target and encode only as needed.",
            "Use traversal depth, absolute paths, nested encodings, and path truncation based on observed filters.",
            "Compare with a known nonexistent file to distinguish filter errors from missing files.",
        ],
        "validation": [
            "Response contains expected file content and differs from controls.",
            "A non-sensitive control path does not return the same content.",
        ],
        "pivot_hints": [
            "Try URL encoding, double encoding, dot-dot stripping bypasses, and absolute path forms.",
            "If suffix is appended, test null-byte style only for legacy or lab-indicated stacks.",
        ],
        "avoid": ["Do not read files unrelated to the authorized lab objective."],
    },
    "csrf": {
        "id": "csrf",
        "vulnerability": "Cross-site request forgery",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js"],
        "recon_goals": [
            "Identify state-changing requests and CSRF token placement.",
            "Check SameSite cookie behavior, method restrictions, Referer/Origin validation, and token binding.",
            "Capture a minimal HTML proof request for the vulnerable action.",
        ],
        "required_artifacts": [
            "state-changing baseline request",
            "token/Origin control observations",
            "browser-delivered proof or lab submission",
        ],
        "exploit_strategy": [
            "Remove or alter token/Origin/Referer one control at a time.",
            "Use GET, form POST, or method override depending on accepted request shape.",
            "For SameSite bypass labs, align navigation method and cookie context.",
        ],
        "validation": [
            "Victim-equivalent browser request performs the state change.",
            "Control request with invalid preconditions fails as expected.",
        ],
        "pivot_hints": [
            "Try token duplication, blank token, token from another session, and method changes.",
            "If SameSite blocks POST, test top-level GET or newly issued cookie scenarios where lab-relevant.",
        ],
        "avoid": ["Do not claim CSRF from a missing token if SameSite/Origin still blocks the action."],
    },
    "cors": {
        "id": "cors",
        "vulnerability": "CORS misconfiguration",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js"],
        "recon_goals": [
            "Find authenticated JSON/API endpoints returning sensitive data.",
            "Test Origin reflection, trusted suffix/prefix parsing, null origin, and credential allowance.",
            "Capture response headers and body under a controlled Origin.",
        ],
        "required_artifacts": [
            "authenticated baseline API response",
            "malicious Origin request with CORS headers",
            "browser-readable sensitive response or lab-solved signal",
        ],
        "exploit_strategy": [
            "Probe one Origin variant at a time and require Access-Control-Allow-Credentials when cookies are needed.",
            "Use browser proof only after headers indicate exploitability.",
            "Target the smallest sensitive endpoint that proves impact.",
        ],
        "validation": [
            "The response allows the malicious Origin and credentials.",
            "Browser JavaScript can read the sensitive response.",
        ],
        "pivot_hints": [
            "Try null origin, subdomain suffix tricks, and parser confusion around trusted domains.",
            "If credentials are not allowed, look for bearer-token or unauthenticated sensitive responses.",
        ],
        "avoid": ["Do not report CORS when the browser cannot read the response."],
    },
    "websocket": {
        "id": "websocket",
        "vulnerability": "WebSocket security flaw",
        "primary_tools": ["browser_navigate", "browser_execute_js", "run_shell", "caido_local_api"],
        "recon_goals": [
            "Find ws/wss endpoints in JS and observe message schema.",
            "Identify auth, origin, CSRF, and server-side rendering behavior in messages.",
            "Capture baseline message/response pairs.",
        ],
        "required_artifacts": [
            "WebSocket endpoint and message schema",
            "crafted message",
            "server response or browser impact proving the bug",
        ],
        "exploit_strategy": [
            "Replay valid messages first, then alter one field or context at a time.",
            "For XSS, determine whether messages are rendered by the sender, recipient, or server.",
            "For authz, compare message behavior across sessions.",
        ],
        "validation": [
            "Crafted WebSocket message produces the lab-required response or execution.",
            "Control message under the wrong session or escaped context fails.",
        ],
        "pivot_hints": [
            "Check Origin validation and whether HTTP cookies alone authenticate the socket.",
            "Mine JS bundles for hidden event names and message fields.",
        ],
        "avoid": ["Do not rely on HTTP-only tooling for final WebSocket proof."],
    },
    "business_logic": {
        "id": "business_logic",
        "vulnerability": "Business logic flaw",
        "primary_tools": ["http_request", "browser_navigate", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Map the intended workflow and every state-changing request.",
            "Identify trust boundaries: price, quantity, role, email, coupon, stock, and sequence assumptions.",
            "Capture baseline state before and after normal workflow completion.",
        ],
        "required_artifacts": [
            "normal workflow baseline",
            "tampered or reordered request sequence",
            "final state proving unauthorized benefit or bypass",
        ],
        "exploit_strategy": [
            "Change one business invariant at a time.",
            "Replay steps out of order, skip validation steps, or reuse single-use values based on observed flow.",
            "Always verify final application state after the request sequence.",
        ],
        "validation": [
            "The final state violates the intended rule and a normal control does not.",
            "Lab solved banner or required object state is observed.",
        ],
        "pivot_hints": [
            "Try negative quantities, price/discount tampering, stale carts, alternate endpoints, and duplicate submissions.",
            "If server validates one path, look for another API path that mutates the same state.",
        ],
        "avoid": ["Do not stop at a single accepted tampered request; confirm business impact."],
    },
    "clickjacking": {
        "id": "clickjacking",
        "vulnerability": "Clickjacking / UI redress",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js"],
        "recon_goals": [
            "Identify sensitive state-changing UI actions that can be framed.",
            "Check X-Frame-Options and Content-Security-Policy frame-ancestors behavior.",
            "Map required login, prefilled form, and click sequence.",
        ],
        "required_artifacts": [
            "target action page and framing header evidence",
            "exploit HTML with iframe overlay and click target alignment",
            "browser-delivered proof or lab-solved signal",
        ],
        "exploit_strategy": [
            "Use browser rendering to measure iframe position, opacity, and button coordinates.",
            "Preserve authenticated victim context and required prefilled parameters.",
            "For multi-step labs, align each required click and verify final state.",
        ],
        "validation": [
            "The page is frameable by the exploit origin.",
            "A victim-equivalent browser click performs the intended state change.",
            "Frame protections are absent or bypassed in the observed response.",
        ],
        "pivot_hints": [
            "If framing is blocked, check whether the vulnerable action lives on a frameable subpage.",
            "If alignment fails, use browser measurements instead of static pixel guesses.",
        ],
        "avoid": ["Do not claim clickjacking from missing headers alone; prove the framed action."],
    },
    "dom_based": {
        "id": "dom_based",
        "vulnerability": "DOM-based vulnerability",
        "primary_tools": ["browser_navigate", "browser_execute_js", "http_request"],
        "recon_goals": [
            "Map browser-side sources: location, hash, search, postMessage, storage, cookies, referrer.",
            "Map sinks: DOM XSS sinks, redirects, cookie writes, WebSocket sends, fetch URLs, and document-domain logic.",
            "Trace source-to-sink data flow in JS bundles before choosing the exploit primitive.",
        ],
        "required_artifacts": [
            "source-to-sink trace",
            "payload delivery path",
            "browser-observed impact or lab-solved signal",
        ],
        "exploit_strategy": [
            "Classify the sink first: script execution, redirect, cookie manipulation, open fetch, or postMessage trust.",
            "Use browser JS to inspect runtime state and prove exploitability.",
            "Choose the smallest payload that triggers the lab-required sink behavior.",
        ],
        "validation": [
            "The payload reaches the sink through browser-side code.",
            "The sink produces security impact, not just DOM mutation.",
            "A control value reaches the same path without the malicious effect.",
        ],
        "pivot_hints": [
            "If hash input fails, test query string, postMessage, storage, and referrer sources.",
            "If one sink is sanitized, search bundles for alternate sinks fed by the same source.",
        ],
        "avoid": ["Do not treat static source-code reachability as exploit proof without browser observation."],
    },
    "xxe": {
        "id": "xxe",
        "vulnerability": "XML external entity injection",
        "primary_tools": ["http_request", "caido_local_api", "oob_get_domain", "oob_poll"],
        "recon_goals": [
            "Find XML endpoints and confirm accepted Content-Type/body structure.",
            "Capture valid baseline XML and parser error behavior.",
            "Determine whether the lab expects in-band file read, SSRF, or blind OOB proof.",
        ],
        "required_artifacts": [
            "valid baseline XML request",
            "DOCTYPE/entity payload",
            "file content, SSRF response, OOB interaction, or lab-solved signal",
        ],
        "exploit_strategy": [
            "Preserve valid XML and add the smallest entity declaration needed.",
            "Use in-band entity expansion when response reflects parsed XML.",
            "Switch to parameter entities or external DTD/OOB when direct output is blocked.",
        ],
        "validation": [
            "Changing the entity target changes the observed response or callback.",
            "A control request without the entity does not produce the same signal.",
        ],
        "pivot_hints": [
            "Try external DTD form if inline DOCTYPE is blocked.",
            "Try SVG/file-upload XML parsers when API XML endpoints are absent.",
        ],
        "avoid": ["Do not claim XXE from parser errors without entity-controlled impact."],
    },
    "authentication": {
        "id": "authentication",
        "vulnerability": "Authentication vulnerability",
        "primary_tools": ["http_request", "browser_navigate", "list_sessions", "swap_session", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Map login, registration, password reset, remember-me, MFA, and account recovery flows.",
            "Capture lockout, error-message, redirect, token, and session-rotation behavior.",
            "Identify username enumeration, logic bypass, weak reset tokens, and flawed MFA states.",
        ],
        "required_artifacts": [
            "baseline failed and valid-flow requests",
            "bypass or enumeration proof",
            "authenticated target account state or lab-solved signal",
        ],
        "exploit_strategy": [
            "Prefer logic flaws, token flaws, and response differentials over brute force.",
            "Use supplied lab credentials and wordlists only where the lab explicitly expects them.",
            "Preserve session transitions and validate account identity after bypass.",
        ],
        "validation": [
            "The agent authenticates as the intended user or bypasses the intended auth control.",
            "Control credentials/tokens fail as expected.",
            "The final session reaches the lab-required account/action.",
        ],
        "pivot_hints": [
            "Try username enumeration via response body, status, timing, and redirects.",
            "For MFA/reset flows, replay steps out of order and test token/session binding.",
        ],
        "avoid": ["Do not brute-force outside explicit lab constraints."],
    },
    "information_disclosure": {
        "id": "information_disclosure",
        "vulnerability": "Information disclosure",
        "primary_tools": ["http_request", "run_shell", "discover_apis", "extract_js_endpoints", "caido_local_api"],
        "recon_goals": [
            "Inspect robots.txt, sitemap, backup files, comments, error pages, headers, JS, and API specs.",
            "Search for hidden endpoints, debug parameters, stack traces, keys, version leaks, and credentials.",
            "Correlate disclosed details with a concrete lab objective or follow-on exploit.",
        ],
        "required_artifacts": [
            "disclosing endpoint/request",
            "sensitive value or hidden functionality",
            "impact proof or lab-solved signal",
        ],
        "exploit_strategy": [
            "Start with low-noise fetches of common disclosure locations and observed links.",
            "Mine JS and API definitions before directory brute forcing.",
            "Use disclosed data immediately to unlock the lab-required action.",
        ],
        "validation": [
            "The response contains sensitive data not intended for the current user.",
            "The disclosed value changes what the agent can access or solve.",
        ],
        "pivot_hints": [
            "If common files fail, inspect error paths, verbose parameters, and source maps.",
            "If a version leaks, pivot to known issue research for that exact component.",
        ],
        "avoid": ["Do not report banner/version disclosure without lab-relevant impact."],
    },
    "host_header": {
        "id": "host_header",
        "vulnerability": "HTTP Host header attack",
        "primary_tools": ["http_request", "caido_local_api", "oob_get_domain", "oob_poll", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Test Host, absolute URL, X-Forwarded-Host, X-Host, Forwarded, and scheme override handling.",
            "Identify password reset poisoning, cache poisoning, auth bypass, virtual host routing, or routing-based SSRF sinks.",
            "Capture cache key and TLS/SNI validation behavior where relevant.",
        ],
        "required_artifacts": [
            "baseline request with original Host",
            "modified Host/header request",
            "poisoned reset link, cached response, bypass, OOB callback, or lab-solved signal",
        ],
        "exploit_strategy": [
            "Change one host-related header at a time and compare response/callback behavior.",
            "For reset poisoning, trigger a reset and inspect generated link host.",
            "For routing SSRF, use OOB first before attempting internal access through the front-end.",
        ],
        "validation": [
            "A host-controlled value reaches a security-sensitive sink.",
            "The final impact is observable through reset link poisoning, cache poisoning, auth bypass, or OOB routing.",
        ],
        "pivot_hints": [
            "Try duplicate Host, absolute-form request target, non-numeric ports, and X-Forwarded-Host variants.",
            "If direct Host is validated, test intermediary override headers.",
        ],
        "avoid": ["Do not claim Host header vulnerability from harmless reflection alone."],
    },
    "oauth": {
        "id": "oauth",
        "vulnerability": "OAuth authentication flaw",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js", "caido_local_api"],
        "recon_goals": [
            "Map authorization, token, redirect_uri, client_id, state, scope, and userinfo requests.",
            "Capture normal browser login flow and callback parameters.",
            "Identify redirect URI validation, state binding, token leakage, account linking, and client registration behavior.",
        ],
        "required_artifacts": [
            "normal OAuth flow trace",
            "modified authorization/token/client request",
            "account takeover, token leak, SSRF, or lab-solved signal",
        ],
        "exploit_strategy": [
            "Replay the exact browser flow while changing one OAuth parameter at a time.",
            "Check state and redirect_uri binding before pursuing account takeover.",
            "Use dynamic client registration playbook when discovery exposes registration endpoints.",
        ],
        "validation": [
            "The modified OAuth flow authenticates or links the wrong account/token.",
            "A control flow with correct binding does not produce the impact.",
        ],
        "pivot_hints": [
            "Try redirect_uri path/query normalization, open redirects, missing state, and account-linking CSRF.",
            "If the provider blocks browser replay, use Caido raw requests while preserving cookies.",
        ],
        "avoid": ["Do not treat a redirect difference as takeover without final account proof."],
    },
    "essential_skills": {
        "id": "essential_skills",
        "vulnerability": "Essential web security lab skill",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js", "caido_local_api", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Read the lab objective, identify the exact success condition, and map the minimal workflow.",
            "Capture baseline requests, cookies, CSRF tokens, and UI state before changing anything.",
            "Keep a strict evidence trail and avoid broad scanning.",
        ],
        "required_artifacts": [
            "baseline workflow",
            "minimal changed request or UI action",
            "lab-solved signal",
        ],
        "exploit_strategy": [
            "Use Caido/history to understand the workflow and choose the smallest test.",
            "Prefer deterministic request replay and browser verification over guessing.",
            "Escalate to a specific vulnerability playbook when evidence identifies one.",
        ],
        "validation": [
            "The lab success condition is met.",
            "The exact request/action that solved it is recorded.",
        ],
        "pivot_hints": [
            "If the category is unclear, run read-only recon and profile detection before exploitation.",
            "If evidence is weak, add a baseline/control request.",
        ],
        "avoid": ["Do not skip objective parsing or proof artifacts."],
    },
    "api_testing": {
        "id": "api_testing",
        "vulnerability": "API testing weakness",
        "primary_tools": ["discover_apis", "extract_js_endpoints", "http_request", "caido_local_api", "list_sessions", "swap_session"],
        "recon_goals": [
            "Discover OpenAPI/Swagger/GraphQL docs, JS API calls, hidden versions, and mobile/API-only endpoints.",
            "Map object IDs, methods, auth requirements, content types, and mass-assignment fields.",
            "Prioritize OWASP API authorization, authentication, inventory, SSRF, and business-flow risks.",
        ],
        "required_artifacts": [
            "API inventory or specification",
            "baseline authorized and unauthorized request",
            "unauthorized data/action, mass assignment, SSRF, or lab-solved signal",
        ],
        "exploit_strategy": [
            "Build a request collection from specs and JS before fuzzing.",
            "Test BOLA/BFLA by swapping object IDs, roles, methods, and sessions.",
            "Test hidden properties and alternative API versions for mass assignment and inventory flaws.",
        ],
        "validation": [
            "A controlled API request violates object, function, property, or workflow authorization.",
            "Control session/object requests demonstrate the intended boundary.",
        ],
        "pivot_hints": [
            "Try v1/v2/beta paths, OPTIONS, schema examples, and undocumented fields.",
            "If auth blocks one endpoint, inspect JS/spec for alternate endpoints serving the same resource.",
        ],
        "avoid": ["Do not brute force API paths before parsing available specs and JS."],
    },
    "web_llm_attacks": {
        "id": "web_llm_attacks",
        "vulnerability": "Web LLM attack",
        "primary_tools": ["http_request", "browser_navigate", "browser_execute_js", "caido_local_api", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Map chat/LLM entry points, tool/API integrations, retrieval sources, and permission boundaries.",
            "Identify direct prompt injection, indirect prompt injection, excessive agency, data leakage, and tool misuse opportunities.",
            "Capture the model-visible action surface and any APIs it can invoke.",
        ],
        "required_artifacts": [
            "baseline LLM prompt/response",
            "injection prompt or malicious content source",
            "unauthorized tool/API action, data leak, or lab-solved signal",
        ],
        "exploit_strategy": [
            "Treat LLM-accessible APIs as attacker-reachable and test authorization at the backing API.",
            "Use direct prompt injection first, then indirect injection through retrievable content when present.",
            "Prove impact with a concrete tool call, data disclosure, or state change.",
        ],
        "validation": [
            "The LLM follows attacker-controlled instructions across the intended trust boundary.",
            "The resulting API/tool action or disclosure is observable and reproducible.",
            "A benign/control prompt does not produce the same impact.",
        ],
        "pivot_hints": [
            "If direct prompts are filtered, inject via stored/retrieved content or tool output.",
            "If the model refuses, target the backing API authorization rather than the prompt wording.",
        ],
        "avoid": ["Do not report a jailbreak without web-app impact."],
    },
    "network_pentest": {
        "id": "network_pentest",
        "vulnerability": "Network host/service compromise",
        "primary_tools": ["nmap_scan", "metasploit_run", "run_shell", "http_request"],
        "recon_goals": [
            "Enumerate open ports and service versions with nmap_scan before touching anything.",
            "Fingerprint each service (banner, version, default creds, known CVEs).",
            "Map which service is the intended foothold for the objective.",
        ],
        "required_artifacts": [
            "structured nmap service map",
            "vulnerable service + version evidence",
            "shell/access proof or objective flag",
        ],
        "exploit_strategy": [
            "Match the service version to a specific exploit before spraying modules.",
            "Use metasploit_run with a targeted module and explicit RHOSTS/RPORT.",
            "Prefer a single precise exploit over broad auto-pwn.",
        ],
        "validation": [
            "A service-specific exploit returns a session, command output, or the flag.",
            "A control request to an unrelated port fails as expected.",
        ],
        "pivot_hints": [
            "If the first service is patched, move to the next open service by heat.",
            "Check default/weak credentials and misconfigurations before memory-corruption exploits.",
        ],
        "avoid": ["Do not scan or exploit hosts outside the authorized scope."],
    },
    "metasploit": {
        "id": "metasploit",
        "vulnerability": "Service exploitation via Metasploit",
        "primary_tools": ["metasploit_run", "msfvenom_generate", "nmap_scan", "run_shell"],
        "recon_goals": [
            "Confirm the exact vulnerable service/version nmap reported.",
            "Search Metasploit for a module matching that product and version.",
            "Identify required options: RHOSTS, RPORT, LHOST, LPORT, PAYLOAD.",
        ],
        "required_artifacts": [
            "chosen module + set options",
            "msfvenom payload when a custom stager is needed",
            "session, command output, or flag proving execution",
        ],
        "exploit_strategy": [
            "Set every required option explicitly and run once via a resource script.",
            "Use check actions where the module supports them before exploit.",
            "Generate payloads with msfvenom_generate matched to the target arch/OS.",
        ],
        "validation": [
            "The module opens a session or yields authenticated command output.",
            "A control run without the exploit precondition fails.",
        ],
        "pivot_hints": [
            "Try alternate payloads (staged vs stageless, TCP vs HTTP) if the handler stalls.",
            "Verify LHOST reachability before blaming the exploit.",
        ],
        "avoid": ["Do not launch destructive or DoS modules against lab targets."],
    },
    "binary_pwn": {
        "id": "binary_pwn",
        "vulnerability": "Binary exploitation (memory corruption)",
        "primary_tools": ["pwn_template", "radare2_analyze", "gdb_debug", "run_shell"],
        "recon_goals": [
            "Run checksec via pwn_template to learn NX, PIE, canary, RELRO.",
            "Map dangerous calls (gets/strcpy/system/read) with radare2_analyze.",
            "Find the overflow offset and any leak primitive with gdb_debug.",
        ],
        "required_artifacts": [
            "protections summary",
            "crash/offset proof (cyclic pattern)",
            "working exploit script producing the flag or shell",
        ],
        "exploit_strategy": [
            "Choose the technique from protections: ret2win, ret2libc, ROP, or shellcode.",
            "Build the exploit incrementally with a pwntools template (local first, then remote).",
            "Leak addresses before defeating ASLR; align the stack before calling libc.",
        ],
        "validation": [
            "The exploit reliably returns a shell or prints the flag against the target.",
            "The same script works against the remote service, not just locally.",
        ],
        "pivot_hints": [
            "If NX blocks shellcode, pivot to ROP/ret2libc.",
            "If a canary is present, find a leak or overwrite path that preserves it.",
        ],
        "avoid": ["Do not hardcode local libc offsets against a remote with a different libc."],
    },
    "reverse_engineering": {
        "id": "reverse_engineering",
        "vulnerability": "Reverse engineering / key recovery",
        "primary_tools": ["radare2_analyze", "gdb_debug", "run_shell", "crypto_helper"],
        "recon_goals": [
            "Identify file type, packing, and language with rabin2/file.",
            "Enumerate functions and strings via radare2_analyze to find the check routine.",
            "Locate the comparison/validation that gates the flag.",
        ],
        "required_artifacts": [
            "function/string map",
            "the validation logic or key-check routine",
            "recovered key/flag or the input that satisfies the check",
        ],
        "exploit_strategy": [
            "Read the decompiled check logic instead of brute forcing.",
            "Use gdb_debug to observe runtime values, patch branches, or dump comparisons.",
            "Reimplement or invert the algorithm to derive the expected input.",
        ],
        "validation": [
            "The recovered input passes the program's own success path.",
            "The derived key/flag matches the objective format.",
        ],
        "pivot_hints": [
            "If statically obfuscated, switch to dynamic analysis and dump the compared buffer.",
            "If packed, unpack or dump memory at the OEP before analysis.",
        ],
        "avoid": ["Do not brute force when the algorithm can be read and inverted."],
    },
    "mobile_android": {
        "id": "mobile_android",
        "vulnerability": "Android application weakness",
        "primary_tools": ["apk_decompile", "apk_analyze", "frida_hook", "run_shell"],
        "recon_goals": [
            "Decompile the APK with apktool (resources) and jadx (Java) via apk_decompile.",
            "Enumerate the manifest, exported components, permissions, and dangerous sinks with apk_analyze.",
            "Locate hardcoded secrets, endpoints, and security checks (root/SSL pinning).",
        ],
        "required_artifacts": [
            "decompiled source tree",
            "manifest + sink/secret inventory",
            "runtime hook output or extracted secret/flag",
        ],
        "exploit_strategy": [
            "Read the smali/Java for the target logic before hooking.",
            "Use frida_hook to bypass root/pinning checks or dump values at runtime.",
            "Chain static findings (endpoint/secret) into a concrete request or action.",
        ],
        "validation": [
            "A hook changes app behavior or reveals the guarded value/flag.",
            "The extracted secret/endpoint yields the objective.",
        ],
        "pivot_hints": [
            "If a check is native, hook libc/JNI exports instead of Java methods.",
            "If jadx fails to decompile, fall back to apktool smali reading.",
        ],
        "avoid": ["Do not repackage or distribute the target app outside the lab."],
    },
    "crypto": {
        "id": "crypto",
        "vulnerability": "Cryptographic weakness",
        "primary_tools": ["crypto_helper", "hash_crack", "run_shell", "flag_hunter"],
        "recon_goals": [
            "Identify the scheme (classical, RSA, AES mode, ECC, hash) and given parameters.",
            "Normalize encodings (base64/hex/binary) with crypto_helper before analysis.",
            "Spot the introduced weakness: small e, shared modulus, ECB, nonce reuse, weak key.",
        ],
        "required_artifacts": [
            "decoded ciphertext + known parameters",
            "the exploited weakness",
            "recovered plaintext/key/flag",
        ],
        "exploit_strategy": [
            "Attack the specific weakness (e.g. RSA low-exponent, padding oracle, XOR key reuse).",
            "Use hash_crack for weak-hash / password challenges.",
            "Reimplement the decryption once the parameters are known.",
        ],
        "validation": [
            "The recovered plaintext matches the expected flag format.",
            "The derived key decrypts a control ciphertext correctly.",
        ],
        "pivot_hints": [
            "If RSA seems hard, check factordb, common factors, and small exponents first.",
            "For classical ciphers, run frequency analysis before assuming a keyed cipher.",
        ],
        "avoid": ["Do not brute force full keyspaces when a mathematical shortcut exists."],
    },
    "stego": {
        "id": "stego",
        "vulnerability": "Steganography / hidden data",
        "primary_tools": ["stego_extract", "forensics_triage", "run_shell", "flag_hunter"],
        "recon_goals": [
            "Fingerprint the carrier file type and inspect metadata (exiftool/strings).",
            "Check for appended/embedded data with binwalk before deep stego tools.",
            "Choose the tool by carrier: steghide/zsteg for images, spectrogram for audio.",
        ],
        "required_artifacts": [
            "carrier analysis (type, metadata, entropy)",
            "extraction command that succeeds",
            "recovered hidden payload/flag",
        ],
        "exploit_strategy": [
            "Layer techniques: strings/exif, then binwalk carve, then LSB/steghide.",
            "Try common/empty passphrases and any wordlist hint for steghide.",
            "Pipe extracted output through flag_hunter.",
        ],
        "validation": [
            "Extraction yields readable content matching the flag format.",
        ],
        "pivot_hints": [
            "If steghide fails, try zsteg (PNG/BMP), outguess, or LSB planes.",
            "For audio, inspect the spectrogram and channel data.",
        ],
        "avoid": ["Do not assume one tool; carriers often stack multiple layers."],
    },
    "forensics": {
        "id": "forensics",
        "vulnerability": "Digital forensics artifact recovery",
        "primary_tools": ["forensics_triage", "stego_extract", "run_shell", "flag_hunter"],
        "recon_goals": [
            "Identify the artifact type: pcap, disk image, memory dump, or file blob.",
            "For pcap, follow streams and extract objects; for images, carve files.",
            "For memory dumps, pick the right volatility profile/plugins.",
        ],
        "required_artifacts": [
            "artifact type + tooling chosen",
            "extracted stream/file/process evidence",
            "recovered flag or objective data",
        ],
        "exploit_strategy": [
            "Use tshark/wireshark filters to isolate the relevant conversation.",
            "Carve with binwalk/foremost, then triage recovered files with flag_hunter.",
            "For memory, enumerate processes, then dump the relevant one.",
        ],
        "validation": [
            "The recovered artifact contains the flag or the required evidence.",
        ],
        "pivot_hints": [
            "If a pcap is TLS-encrypted, look for keys/SSLKEYLOGFILE in the challenge files.",
            "If carving finds fragments, reassemble by known file signatures.",
        ],
        "avoid": ["Do not ignore file metadata and slack space; flags often hide there."],
    },
    "ctf_misc": {
        "id": "ctf_misc",
        "vulnerability": "Miscellaneous CTF challenge",
        "primary_tools": ["run_shell", "flag_hunter", "crypto_helper", "web_search"],
        "recon_goals": [
            "Read the prompt and provided files to classify the real category.",
            "Fingerprint every provided file (file, strings, exiftool, binwalk).",
            "Decide whether the task is crypto, stego, forensics, binary, or web.",
        ],
        "required_artifacts": [
            "file/prompt analysis",
            "the technique that fits the actual category",
            "recovered flag",
        ],
        "exploit_strategy": [
            "Start with cheap universal probes (strings, flag_hunter, metadata).",
            "Re-route to the specific category playbook once the type is clear.",
            "Use web_search for unusual formats or known challenge patterns.",
        ],
        "validation": [
            "Output contains a string matching the challenge flag format.",
        ],
        "pivot_hints": [
            "If nothing obvious, re-read the prompt for the intended trick.",
            "Combine techniques (decode then decrypt then flag-hunt).",
        ],
        "avoid": ["Do not fixate on one category before fingerprinting the files."],
    },
    "web_cache_deception": {
        "id": "web_cache_deception",
        "vulnerability": "Web cache deception",
        "primary_tools": ["http_request", "caido_local_api", "capture_baseline", "diff_against_baseline"],
        "recon_goals": [
            "Identify dynamic GET endpoints containing user-specific or sensitive data.",
            "Map cache rules based on static extensions, static directories, path normalization, delimiters, and cache headers.",
            "Use cache busters while testing to avoid stale false positives.",
        ],
        "required_artifacts": [
            "dynamic sensitive baseline response",
            "deception URL using cache/origin parser discrepancy",
            "follow-up cached response containing victim-equivalent sensitive data",
        ],
        "exploit_strategy": [
            "Find a dynamic page that the origin serves despite an added static-looking path segment.",
            "Confirm the cache stores that same URL using X-Cache/age/timing and repeated requests.",
            "Fetch the cached response with a victim-equivalent path to prove exposure.",
        ],
        "validation": [
            "The crafted URL causes a dynamic response to be cached.",
            "A later request receives the cached sensitive response.",
            "A distinct cache key/control URL does not show the same data.",
        ],
        "pivot_hints": [
            "Try static extension, static directory, delimiter, and encoded path traversal discrepancies.",
            "If the browser hides redirects or local state, use raw HTTP/Caido for verification.",
        ],
        "avoid": ["Do not confuse web cache deception with poisoning; deception exposes cached private dynamic content."],
    },
}


ALIASES: list[tuple[str, str]] = [
    ("dynamic client registration", "oauth_ssrf_dynamic_registration"),
    ("openid", "oauth_ssrf_dynamic_registration"),
    ("oidc", "oauth_ssrf_dynamic_registration"),
    ("oauth authentication", "oauth"),
    ("oauth", "oauth"),
    ("blind xxe", "blind_xxe_oob"),
    ("out-of-band xxe", "blind_xxe_oob"),
    ("xml external", "xxe"),
    ("xxe", "xxe"),
    ("command injection", "os_command_injection"),
    ("os command", "os_command_injection"),
    ("cmdi", "os_command_injection"),
    ("nosql", "nosql_injection"),
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("jwt", "jwt"),
    ("json web token", "jwt"),
    ("access control", "access_control_idor"),
    ("idor", "access_control_idor"),
    ("insecure direct object", "access_control_idor"),
    ("request smuggling", "request_smuggling"),
    ("desync", "request_smuggling"),
    ("cache deception", "web_cache_deception"),
    ("web cache deception", "web_cache_deception"),
    ("cache poisoning", "web_cache_poisoning"),
    ("web cache", "web_cache_poisoning"),
    ("template injection", "ssti"),
    ("ssti", "ssti"),
    ("deserialization", "deserialization"),
    ("deserialisation", "deserialization"),
    ("prototype pollution", "prototype_pollution"),
    ("graphql", "graphql_api"),
    ("graph ql", "graphql_api"),
    ("race condition", "race_condition"),
    ("race conditions", "race_condition"),
    ("dom-based vulnerabilities", "dom_based"),
    ("dom-based vulnerability", "dom_based"),
    ("dom vulnerabilities", "dom_based"),
    ("dom xss", "dom_xss"),
    ("dom-based xss", "dom_xss"),
    ("cross-site scripting", "xss"),
    ("xss", "xss"),
    ("file upload", "file_upload"),
    ("path traversal", "path_traversal"),
    ("file path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("csrf", "csrf"),
    ("cross-site request forgery", "csrf"),
    ("cors", "cors"),
    ("cross-origin resource sharing", "cors"),
    ("clickjacking", "clickjacking"),
    ("ui redress", "clickjacking"),
    ("authentication", "authentication"),
    ("information disclosure", "information_disclosure"),
    ("info disclosure", "information_disclosure"),
    ("host header", "host_header"),
    ("http host", "host_header"),
    ("websocket", "websocket"),
    ("web socket", "websocket"),
    ("business logic", "business_logic"),
    ("logic flaw", "business_logic"),
    ("essential skills", "essential_skills"),
    ("api testing", "api_testing"),
    ("api security", "api_testing"),
    ("web llm", "web_llm_attacks"),
    ("llm attacks", "web_llm_attacks"),
    ("large language model", "web_llm_attacks"),
    ("ssrf", "ssrf"),
    ("network pentest", "network_pentest"),
    ("network penetration", "network_pentest"),
    ("service enumeration", "network_pentest"),
    ("metasploit", "metasploit"),
    ("msfconsole", "metasploit"),
    ("binary pwn", "binary_pwn"),
    ("binary exploitation", "binary_pwn"),
    ("buffer overflow", "binary_pwn"),
    ("pwn", "binary_pwn"),
    ("rop", "binary_pwn"),
    ("reverse engineering", "reverse_engineering"),
    ("reverse-engineering", "reverse_engineering"),
    ("crackme", "reverse_engineering"),
    ("mobile android", "mobile_android"),
    ("android app", "mobile_android"),
    ("apk", "mobile_android"),
    ("frida", "mobile_android"),
    ("crypto", "crypto"),
    ("cryptography", "crypto"),
    ("cipher", "crypto"),
    ("rsa", "crypto"),
    ("stego", "stego"),
    ("steganography", "stego"),
    ("forensics", "forensics"),
    ("forensic", "forensics"),
    ("pcap", "forensics"),
    ("memory dump", "forensics"),
    ("ctf misc", "ctf_misc"),
    ("misc challenge", "ctf_misc"),
]


def normalize_vuln_key(value: str | None) -> str:
    """Map free-form vulnerability text to a playbook key."""
    text = (value or "").strip().lower().replace("_", " ")
    if not text:
        return ""
    if text in EXPERT_PLAYBOOKS:
        return text
    for needle, key in ALIASES:
        if needle in text:
            return key
    return text.replace(" ", "_")


def get_playbook(key_or_profile: str | dict[str, Any] | None) -> Playbook | None:
    """Return a defensive copy of a playbook, if one matches."""
    if isinstance(key_or_profile, dict):
        embedded = key_or_profile.get("expert_playbook")
        if isinstance(embedded, dict) and embedded.get("id"):
            return deepcopy(embedded)
        candidates = [
            key_or_profile.get("playbook_id"),
            key_or_profile.get("vulnerability"),
            key_or_profile.get("id"),
            key_or_profile.get("purpose"),
        ]
        key = normalize_vuln_key(" ".join(str(c) for c in candidates if c))
    else:
        key = normalize_vuln_key(key_or_profile)
    playbook = EXPERT_PLAYBOOKS.get(key)
    return deepcopy(playbook) if playbook else None


def enrich_lab_profile(profile: dict[str, Any] | None, objective: str = "") -> dict[str, Any]:
    """Attach playbook metadata to a detected lab profile."""
    if not profile:
        return {}
    enriched = dict(profile)
    if objective and "objective_excerpt" not in enriched:
        enriched["objective_excerpt"] = objective[:500]

    lookup_text = " ".join(
        str(v)
        for v in (
            enriched.get("playbook_id"),
            enriched.get("vulnerability"),
            enriched.get("id"),
            enriched.get("purpose"),
            objective,
        )
        if v
    )
    playbook = get_playbook(lookup_text)
    if not playbook:
        return enriched

    enriched.setdefault("playbook_id", playbook["id"])
    enriched.setdefault("expert_playbook", playbook)
    enriched.setdefault("primary_tools", playbook.get("primary_tools", []))
    enriched.setdefault("required_artifacts", playbook.get("required_artifacts", []))
    enriched.setdefault("success_indicators", playbook.get("validation", []))
    return enriched


def _bullets(items: list[Any], limit: int) -> list[str]:
    return [f"  - {str(item)}" for item in items[:limit]]


def render_playbook_context(profile_or_key: str | dict[str, Any] | None) -> str:
    """Render compact prompt context for specialist agents."""
    playbook = get_playbook(profile_or_key)
    if not playbook:
        return ""

    lines: list[str] = [
        "# EXPERT LAB PLAYBOOK",
        f"id: {playbook.get('id')}",
        f"vulnerability: {playbook.get('vulnerability')}",
        f"primary_tools: {', '.join(playbook.get('primary_tools', []))}",
        "",
        "recon_goals:",
        *_bullets(playbook.get("recon_goals", []), 4),
        "",
        "required_artifacts:",
        *_bullets(playbook.get("required_artifacts", []), 4),
        "",
        "exploit_strategy:",
        *_bullets(playbook.get("exploit_strategy", []), 4),
        "",
        "validation:",
        *_bullets(playbook.get("validation", []), 4),
        "",
        "pivot_hints:",
        *_bullets(playbook.get("pivot_hints", []), 4),
    ]
    avoid = playbook.get("avoid") or []
    if avoid:
        lines.extend(["", "avoid:", *_bullets(avoid, 3)])
    return "\n".join(lines)

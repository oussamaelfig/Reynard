# PortSwigger Expert Coverage Matrix

This matrix maps the Web Security Academy topic taxonomy to Reynard expert
playbooks. The topic list is based on PortSwigger's official "All topics" page.

| PortSwigger topic | Reynard playbook | Official reference |
| --- | --- | --- |
| SQL injection | `sqli` | https://portswigger.net/web-security/sql-injection |
| Cross-site scripting | `xss` | https://portswigger.net/web-security/cross-site-scripting |
| Cross-site request forgery (CSRF) | `csrf` | https://portswigger.net/web-security/csrf |
| Clickjacking | `clickjacking` | https://portswigger.net/web-security/clickjacking |
| DOM-based vulnerabilities | `dom_based` | https://portswigger.net/web-security/dom-based |
| Cross-origin resource sharing (CORS) | `cors` | https://portswigger.net/web-security/cors |
| XML external entity (XXE) injection | `xxe` | https://portswigger.net/web-security/xxe |
| Server-side request forgery (SSRF) | `ssrf` | https://portswigger.net/web-security/ssrf |
| HTTP request smuggling | `request_smuggling` | https://portswigger.net/web-security/request-smuggling |
| OS command injection | `os_command_injection` | https://portswigger.net/web-security/os-command-injection |
| Server-side template injection | `ssti` | https://portswigger.net/web-security/server-side-template-injection |
| Path traversal | `path_traversal` | https://portswigger.net/web-security/file-path-traversal |
| Access control vulnerabilities | `access_control_idor` | https://portswigger.net/web-security/access-control |
| Authentication | `authentication` | https://portswigger.net/web-security/authentication |
| WebSockets | `websocket` | https://portswigger.net/web-security/websockets |
| Web cache poisoning | `web_cache_poisoning` | https://portswigger.net/web-security/web-cache-poisoning |
| Insecure deserialization | `deserialization` | https://portswigger.net/web-security/deserialization |
| Information disclosure | `information_disclosure` | https://portswigger.net/web-security/information-disclosure |
| Business logic vulnerabilities | `business_logic` | https://portswigger.net/web-security/logic-flaws |
| HTTP Host header attacks | `host_header` | https://portswigger.net/web-security/host-header |
| OAuth authentication | `oauth` | https://portswigger.net/web-security/oauth |
| File upload vulnerabilities | `file_upload` | https://portswigger.net/web-security/file-upload |
| JWT | `jwt` | https://portswigger.net/web-security/jwt |
| Essential skills | `essential_skills` | https://portswigger.net/web-security/essential-skills |
| Prototype pollution | `prototype_pollution` | https://portswigger.net/web-security/prototype-pollution |
| GraphQL API vulnerabilities | `graphql_api` | https://portswigger.net/web-security/graphql |
| Race conditions | `race_condition` | https://portswigger.net/web-security/race-conditions |
| NoSQL injection | `nosql_injection` | https://portswigger.net/web-security/nosql-injection |
| API testing | `api_testing` | https://portswigger.net/web-security/api-testing |
| Web LLM attacks | `web_llm_attacks` | https://portswigger.net/web-security/llm-attacks |
| Web cache deception | `web_cache_deception` | https://portswigger.net/web-security/web-cache-deception |

## Supplemental References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Implementation Guarantees

- Each topic has a deterministic playbook in `src/hacking_agent/core/expert_playbooks.py`.
- `detect_lab_profile()` maps each topic to a PortSwigger lab profile when the
  objective names the category.
- `reynard-lab-eval` includes a default suite covering all topics plus the
  specific OIDC dynamic registration SSRF expert case.
- Regression tests assert that every listed category has a playbook and scores
  at least `8/10` in the offline readiness evaluator.

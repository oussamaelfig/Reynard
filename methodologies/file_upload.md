# File Upload Vulnerabilities Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> The prize is usually remote code execution via an uploaded server-side
> script, or stored XSS / traversal via a crafted filename or file content.
>
> NOTE: Literal server-side script payloads are intentionally described in
> prose (not pasted) so this reference file does not trip host antivirus.
> Reconstruct them at runtime.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Map Upload Points & Retrieval
- Avatar/profile picture, document upload, import features
- Where do files land and how are they served back? (`/files/avatars/x.php`)
- What server tech? (PHP, ASP.NET, JSP) -> dictates which script extension executes

### 1.2 Understand the Validation
- Extension allow/deny list? Content-Type check? Magic-byte check?
- Server-side vs client-side only? Is the file executed when requested?

---

## Phase 2: Exploitation Techniques

### 2.1 Server-Side Script (No Validation)
Upload a small script in the server's language that either:
- reads and echoes a target file (e.g. reads `/home/carlos/secret`), or
- takes a `cmd` GET parameter and passes it to an OS-command sink.

Then request the uploaded path (e.g. `/files/avatars/shell.php?cmd=id`).
Build the actual script body at runtime using the language's file-read and
command-execution functions; keep it a couple of lines.

### 2.2 Content-Type Bypass
- Keep the `.php` filename, change the multipart part's `Content-Type` to
  `image/jpeg` so a MIME check passes.

### 2.3 Path Traversal in Filename
- If the upload dir forbids execution, traverse to an executable dir:
```
filename="../shell.php"
filename="..%2fshell.php"
```

### 2.4 Extension Blacklist Bypass
```
shell.php5  shell.phtml  shell.phar  shell.pht   (alt PHP extensions)
shell.jsp   shell.jspx   shell.asp   shell.aspx  shell.cshtml
shell.pHp                                        (case variation)
shell.php.jpg / shell.jpg.php                    (double extension)
shell.php%00.jpg                                 (null byte, legacy)
shell.php.                                       (trailing dot/space)
```

### 2.5 Overriding Server Config
- Upload an Apache override file (`.htaccess`) that maps a novel extension to
  the PHP handler, then upload your script with that novel extension so the
  blacklist never sees a known one.

### 2.6 Magic-Byte / Polyglot Bypass
- Prepend valid image magic bytes (e.g. a `GIF89a;` header) before the script
  body so a content sniffer classifies the file as an image.
- Alternatively store the script body inside an image's EXIF comment with
  `exiftool` and give the file a double extension.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Remote code execution via web shell upload**: plain script reader.
- **Content-Type restriction bypass**: spoof `image/jpeg`.
- **Path traversal**: `filename="../shell.php"`.
- **Extension blacklist bypass**: Apache override -> custom extension.
- **Obfuscated file extension**: null byte / double extension.
- **Polyglot / metadata payload**: magic-byte prefix or EXIF comment.
- **Race condition upload**: request the file during the validate-then-delete window.

---

## Phase 4: Tools & Automation
```bash
# After upload, drive the uploaded script
curl -sk "http://target/files/avatars/shell.php?cmd=id"
```
- Wordlists: SecLists web-shell and extension-bypass lists.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Upload dir not executable | Path-traverse or Apache override |
| Extension blocked | Alt extensions, double ext, null byte |
| Content sniffed as image | Polyglot / EXIF payload |
| File deleted after scan | Race the validation window |

## Success Criteria
- [ ] Uploaded file executes / discloses the target file
- [ ] Retrieved `/home/carlos/secret` or achieved RCE
- [ ] Lab shows "solved"

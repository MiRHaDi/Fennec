---
slug: information-disclosure
applies_to: [pentester]
owasp: A05
related: [authentication_jwt, ssrf, subdomain_takeover]
---

# Information Disclosure — Pentester Playbook

> Load this when recon turned up debug endpoints, source maps, exposed
> config files, verbose error messages, or anything that leaks internals
> the application didn't mean to expose.

## When to load this

The endpoint shapes that bleed info:

- Debug / admin paths surfaced by gobuster (`/.git/`, `/debug/`, `/actuator/`, `/server-status`)
- 500/502/503 responses with stack traces in the body
- Source maps (`*.js.map`) referenced from production HTML
- API responses with `_debug`, `_internal`, `__proto__`, `extra` fields that leak in non-prod modes
- Backup files (`.bak`, `.old`, `.orig`, `~`, `.swp`)
- `robots.txt`, `sitemap.xml`, `humans.txt`, `.well-known/security.txt` (sometimes useful, sometimes leaks paths)
- HTTP response headers (`Server`, `X-Powered-By`, `X-Generator`, custom `X-App-Version`)
- Verbose authentication errors that distinguish "user doesn't exist" from "wrong password"
- Timing differences in auth endpoints
- Cache headers that reveal internal hostnames (`Via: 1.1 internal-cache-7.corp`)

## What you're looking for

Five categories, ranked roughly by impact:

- **Secrets in source / config / git.** API keys, DB credentials, signing keys committed to a public-facing path.
- **Sensitive PII leak.** User emails, addresses, payment info in responses or in indexed pages.
- **Internal architecture leak.** Hostnames, IPs, software versions, dependency graphs — useful for an attacker planning the next stage.
- **Auth flow leak.** Username enumeration, MFA enrollment status, role disclosure on the wrong endpoint.
- **Functional leak.** Source code, API documentation, internal admin URLs, debug interfaces.

## First moves

1. **Source code / git probes.** From recon's path list, check the high-yield paths:
   - `/.git/HEAD`, `/.git/config`, `/.git/index` — if any return 200 with content, the `.git` directory is exposed. Pull the whole repo with `git-dumper`.
   - `/.svn/entries`, `/.hg/`, `/.bzr/` for the niche VCSes
   - `/.env`, `/config.json`, `/application.yml`, `/web.config`, `/database.yml`
   - `/composer.json`, `/package.json`, `/Gemfile`, `/requirements.txt` — usually fine to expose but reveals dependency versions
   - `/composer.lock`, `/package-lock.json`, `/yarn.lock`, `/Gemfile.lock`, `/Pipfile.lock` — same but more detail
   - `/wp-config.php`, `/wp-config.php.bak`, `/wp-config.old` — Wordpress-specific
   - `/server-status`, `/server-info` (Apache mod_status)
   - `/actuator/env`, `/actuator/health`, `/actuator/heapdump`, `/actuator/threaddump` (Spring Boot)
   - `/api/swagger.json`, `/openapi.json`, `/v2/api-docs` (Swagger/OpenAPI specs reveal undocumented endpoints)

2. **Source map probe.** Pull every `.js` file referenced by the app. For each, check for a `//# sourceMappingURL=...` comment. If `app.bundle.js.map` exists, you have the original source code — TS, React, original variable names, the whole thing.

3. **Error-induced leak.** Send malformed requests to each API endpoint: oversized body, invalid Content-Type, null bytes, deeply nested JSON, Unicode noncharacters. Read the response body. Stack traces frequently leak file paths, library versions, internal hostnames.

4. **Header inventory.** Run a single `curl -sI` against each endpoint and inventory unusual headers. `Server: nginx/1.19.0` is mundane; `X-AspNet-Version: 4.0.30319`, `X-Powered-By: PHP/7.4.3-prerelease`, `X-Application-Context: production:8080` are all goldmines for the analyst.

5. **Backup file sweep.** For each main file (`/index.php`, `/login.aspx`, `/style.css`) try the backup suffixes: `.bak`, `.old`, `.orig`, `.tmp`, `~`, `.swp`, `.swo`, `.save`, `.copy`, `.1`, `.2`. Editors leave these constantly.

6. **Auth enumeration check.** Submit invalid login with a known-good username and a known-bad username, separately. Compare response codes, body length, response time. Differences across these signal user enumeration.

7. **Timing sniff.** Same enumeration probe but measure time — bcrypt-validated wrong passwords take ~100ms, "user doesn't exist" responses return in <10ms because there's no hash to validate.

## Confirming a hit

Confirmation is "I extracted the thing." Don't report "looks like a stack trace leak" — extract and quote the leaked content.

- **Source code.** Show a file you downloaded with sensitive content (`.env`, a controller file with hardcoded credentials).
- **Stack traces.** Quote the actual stack frame chain showing the file path and library version.
- **API specs.** Show one undocumented endpoint you found in the swagger that wasn't in the public docs.
- **Secrets.** Confirm a leaked credential actually works (log into the DB, call the API with the key, etc. — bounded by scope).
- **PII.** Quote one record (with the values redacted in the finding if you're cautious, but proving you had access).

## Going deeper — by leak channel

### `.git` directory exposed
```
wget -q "https://target.com/.git/HEAD"
# returns "ref: refs/heads/main" → exposed
git-dumper https://target.com/.git/ ./loot
cd loot && git log --all && git stash list
git log --all -- .env  # find when secrets were committed
```
Even if the deployer ran `rm .env` before push, git history retains it. Check `git log --all -p | grep -E 'PASSWORD|SECRET|KEY|TOKEN'`.

### Source maps
```
curl -sS "https://target.com/static/app.bundle.js.map" -o app.map
# Use Sourcemap Reverser or just JSON-parse and walk 'sources'/'sourcesContent'
python3 -c "import json; m=json.load(open('app.map')); print('\n'.join(m['sources']))"
```
You'll get the full original file paths and content. Search the content for `apiKey`, `endpoint`, `internal`, `staging`, internal company names.

### Spring Boot actuator
The unauth-by-default endpoints in old Spring Boot versions:
- `/actuator/heapdump` — entire heap as `.hprof`, includes plaintext credentials, JWT secrets, DB connection strings
- `/actuator/env` — every env var, including secrets
- `/actuator/configprops` — every Spring config property with current value
- `/actuator/loggers` — list of loggers (less useful)
- `/actuator/mappings` — every endpoint the app exposes (great for discovering hidden APIs)
- `/actuator/threaddump` — every running thread's stack, can reveal in-flight request data

### `.DS_Store` (Mac dev artifacts)
Macs leave `.DS_Store` files in every directory they're browsed in. These contain a list of all filenames in the directory — including hidden ones. `wget https://target.com/.DS_Store` then `python3 -m ds_store_parser` reveals files you wouldn't know to ask for.

### `phpinfo.php`
PHP devs sometimes drop `phpinfo.php` in webroots to debug, then forget. Reveals: PHP version, every loaded extension, every environment variable, the full config, server's filesystem layout. The whole machine's profile in one HTTP response.

### `crossdomain.xml` / `clientaccesspolicy.xml` (Flash/Silverlight leftovers)
Old CORS-equivalents. Loose policies (`<allow-access-from domain="*"/>`) reveal that the app once trusted any origin and may still trust some unexpected ones.

### `robots.txt`
Often lists admin paths the dev wanted to hide from search engines: `Disallow: /admin/internal/`. The fact that they Disallowed it = they thought it was sensitive enough to hide from Google.

### Username enumeration patterns
- **Login error wording.** "User not found" vs "Invalid password."
- **Password reset wording.** "If your email exists, we sent a link" — many apps still leak via response time even with the right wording.
- **Signup uniqueness check.** Real-time "username taken" check during signup is a built-in enumeration oracle.
- **OAuth provider differences.** "Sign in with Google" with a non-existent account vs an existing one — sometimes IdP loops back to the app, which leaks via the loop.

## When filters get in the way

- **WAF blocking common probes.** Try double-encoding (`%2e%2egit/HEAD`), case folding (`/.Git/HEAD`), trailing-slash (`/.git/HEAD/`).
- **Custom 404 page hiding the difference.** WAFs sometimes return a generic 404 that's the same byte length whether the file exists or not. Look for second-order signals: response time, Etag presence, server header differences.
- **Auth-required on admin endpoints but not on subpaths.** `/admin/` returns 401 but `/admin/static/css/style.css` returns 200 — listing the CSS sometimes leaks the admin UI's structure.
- **Verbose errors in dev but not prod.** If the target has a staging or dev subdomain (recon should have found this), check there first. Dev environments leak everything.

## Escalation paths

1. **Secrets → other systems.** Leaked DB credential gives DB access. Leaked AWS key gives S3/EC2 access. Leaked Stripe key lets you initiate charges/refunds. Always test what the leaked credential actually unlocks.
2. **Source code → vulnerability discovery.** With source you can grep for `eval`, `unsafe`, `TODO: fix security`, `password = `, etc. Often turns into other finding categories — RCE via deserialization gadget chains, hardcoded credentials, business logic flaws you couldn't see black-box.
3. **API spec → hidden endpoint enumeration.** Swagger reveals endpoints not in any UI. Many of these are admin/internal and unprotected.
4. **Heap dump → token / session theft.** Spring Boot heapdump contains all in-flight session tokens. Steal active admin sessions.
5. **Username enumeration → password spraying.** Enumerated user list + common-password spray = mass account takeover.

## What a real finding looks like

- The URL or request that triggers the leak
- The actual content extracted (redacted as appropriate for the finding writeup, but preserved in the evidence appendix)
- The path from leak to impact ("via leaked .env we obtained the AWS access key; via that we listed the `target-prod-backups` S3 bucket; bucket contains daily DB dumps including the users table")
- The fix specific to the leak channel: remove the file, secure the actuator with auth, configure the error handler to not leak in production, normalize auth responses

## Common false positives

- **Headers that look version-y but aren't.** `Server: cloudflare` reveals only that they use Cloudflare. Useful context, not a finding.
- **Stack traces in dev environments.** If the only place leaking is `dev.target.com` and it's intentionally a debug environment, it's working as designed.
- **Public sitemaps.** A `sitemap.xml` listing `/blog/post-123` is intentional. Not a leak.
- **OpenAPI spec for a public API.** Apps that publish their own API docs aren't leaking — they're advertising.
- **`robots.txt` listing the marketing site's old paths.** Common, mostly harmless.

## Related skills

`authentication_jwt` for what to do with leaked tokens/secrets, `ssrf` for the internal-network reach that leaked hostnames enable, `subdomain_takeover` for the staging/dev environment angles.

---
slug: sql-injection
applies_to: [pentester, coder]
owasp: A03
related: [authentication_jwt, idor, business_logic]
---

# SQL Injection — Pentester Playbook

> Load this when the analyst flags any endpoint whose handler builds a query
> from user input — search filters, sort parameters, login forms, report
> generators, anything that takes a string and ends up touching the DB.

## When to load this

Three signals from recon that make SQLi the obvious first hypothesis:

- The handler echoes filter values back into the response (suggests templating, often suggests query concatenation)
- The endpoint accepts free-form sort/order parameters (`?order_by=name` is a classic raw-concat target)
- 500 responses leak DB-shaped strings: SQL keywords, stack traces from `psycopg2`, `mysql.connector`, `pyodbc`, JDBC drivers, ORM internals

## What you're looking for

Forget the DBMS for a moment — the bug is **string concatenation between untrusted input and a SQL statement**. That concatenation can happen in any of these spots, and Fennec recon usually surfaces the first two:

- **Value position** inside a WHERE/HAVING/ORDER predicate (`WHERE id = $input`) — the bread-and-butter case
- **Identifier position** (column or table name interpolated from input) — common in admin panels and report builders, often missed by ORMs
- **Operator position** (the comparison operator itself is taken from input — rare but devastating)
- **Inside raw escape hatches** of an ORM (`Model.objects.raw(...)`, `db.exec(...)`, `whereRaw`, `orderByRaw`) — always grep the source for these before testing
- **Inside JSON/array operator strings** (Postgres `@>`, `?`, MySQL `JSON_EXTRACT` paths) where the ORM lets you write raw operator expressions
- **Inside bulk/batch endpoints** that build IN-lists by joining strings

If you have source, grep first: `grep -rE "(execute|query)\\(.*[\"'][^\"']*\\+|f[\"'][^\"']*\\{.*SELECT|format.*SELECT" .` catches most of it.

## First moves

Cheap, low-noise probes. Do these in order — don't fire all of them in parallel until you've ruled out the obvious:

1. **Single quote test.** Append `'` to one parameter at a time and read the response. Look for a 500, a stack trace, or a body diff that mentions SQL.
2. **Quoted equality.** Send `' OR '1'='1` and the matching `' OR '1'='2`. A response diff (200 vs 401, full list vs empty list) confirms boolean control.
3. **Arithmetic identity.** For numeric params: send `1`, then `2-1`, then `1 OR 1=1`. If the response is identical for the first two and broader for the third, the param is being parsed as SQL.
4. **Comment-tail probe.** Append `-- -` or `# `. If the response stays clean (no syntax error, no truncation) the parser is honoring SQL comments.
5. **Order-by probe.** If a `sort=` or `order_by=` parameter exists, send `name) UNION SELECT NULL-- -` and watch for column-count errors. Order-by injection is the single highest-hit-rate channel against modern web apps.

If none of these move the needle, hand sqlmap the request with `--batch --risk=3 --level=5 --random-agent --tamper=space2comment` and let it brute-force the channel for you while you move to the next hypothesis.

## Confirming a hit

You need **two** independent signals before logging a finding. Pick the quietest pair you can:

### Reflected error
Trigger a parser error and read it from the response body. PostgreSQL leaks the position of the syntax error (`ERROR: syntax error at or near "X" at position N`), MySQL leaks the version banner, MSSQL leaks via `Conversion failed when converting...`. If the response shows you the broken token you injected, you have the bug.

### Boolean differential
Send two requests that differ only in the truth of an injected predicate. The diff has to be **stable** — re-run each three times to rule out templating noise, caching, or analytics-driven jitter. If `' AND 1=1-- -` consistently returns one body shape and `' AND 1=2-- -` returns another, you have a blind channel.

### Time-gated confirmation
For when you have no body diff: gate `SLEEP(3)` (MySQL), `pg_sleep(3)` (Postgres), or `WAITFOR DELAY '0:0:3'` (MSSQL) behind a predicate. Always gate the sleep inside a subselect: `AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE 0 END)`. Naked `OR pg_sleep(3)` triggers on every row and produces multi-minute hangs that look like a downed app.

### Out-of-band callback
The cleanest confirmation when you have an OAST endpoint (Burp Collaborator, Interactsh, or our own DNS log target). Postgres `dblink`, MySQL `LOAD_FILE` with a UNC path, MSSQL `xp_dirtree` — each can push a DNS query to a host you control with a token derived from `current_user()` or similar. If the DNS arrives, the bug is confirmed AND you've proven egress.

## Going deeper — by DB

Once you've confirmed which DB is behind the endpoint, switch into the right dialect's pocket guide:

**MySQL / MariaDB.** Reconnaissance functions: `version()`, `database()`, `user()`, `@@hostname`. UNION extraction works against MySQL more reliably than any other DB — find column count with `ORDER BY n` (binary search), then `UNION SELECT NULL,NULL,...` aligning types with `CAST(x AS CHAR)`. File primitives need `FILE` privilege AND `secure_file_priv=NULL` — both rare in modern stacks. `SLEEP(n)` is the default time oracle.

**PostgreSQL.** Reconnaissance: `version()`, `current_database()`, `current_user`, `inet_server_addr()`. Postgres has a richer error surface — provoke errors with `1/(SELECT CAST(x AS INTEGER))` to leak data into the error message. `pg_sleep(n)` for timing. Extensions matter enormously: if `pg_read_server_files` or `dblink` is installed and you have superuser, file IO and outbound HTTP are on the menu. JSONB operators (`@>`, `?|`) are heavily under-tested attack surface in ORM contexts.

**MSSQL.** Reconnaissance: `@@version`, `db_name()`, `system_user`. The killer primitives are `xp_dirtree` for SMB/DNS callback (works even on locked-down servers) and `OPENROWSET` for query federation. `WAITFOR DELAY '0:0:n'` for timing. `xp_cmdshell` is the OS-shell holy grail but is almost always disabled — try `sp_oacreate` for OLE automation as a fallback if you have sysadmin.

**Oracle.** Reconnaissance: `(SELECT banner FROM v$version WHERE rownum=1)`, `user`, `(SELECT ora_database_name FROM dual)`. Out-of-band via `UTL_HTTP.REQUEST` or `DBMS_LDAP` (permission-dependent). Time via `dbms_lock.sleep(n)`. Error-based via `XMLType()` is the most reliable extraction channel against modern Oracle.

**SQLite.** Often forgotten — embedded in mobile backends, electron apps, IoT firmware. No `SLEEP`; force timing via `randomblob(100000000)` recursion. Error messages are sparse. Look for `sqlite_master` to enumerate schema.

## When filters get in the way

A WAF or input validator usually blocks the obvious. Order of bypasses to try:

- **Whitespace substitution.** Tabs, newlines, `/**/`, `/*!50000 */` (MySQL versioned comments) all parse as whitespace. `0xA0` (non-breaking space) bypasses some naive `[\s]+` filters.
- **Comment-token injection.** `UNI/**/ON SEL/**/ECT` defeats keyword blocklists that don't normalize comments first.
- **Case folding.** `UnIoN sElEcT` against case-sensitive regex filters.
- **Double URL-encoding.** `%2527` decodes to `%27` after one decode and `'` after two — works against gateways that decode once before validating.
- **Unicode normalization.** Fullwidth `＇` (U+FF07) or modifier letter apostrophe `ʼ` can survive a strip-quotes filter and still be normalized to `'` by the DB driver. NFKC normalization in the app layer is the friend of injection here.
- **Operator avoidance.** If `OR` is blocked, use `||` (string concat, parses as logical OR in MySQL with `PIPES_AS_CONCAT` off). If `UNION` is blocked, use `;SELECT ...` (works on stacked-query-enabled drivers — pyodbc, sqlite, MSSQL).
- **Logical equivalence.** Replace `AND 1=1` with `AND ASCII(SUBSTR(database(),1,1))>0` — same truth, no `1=1` literal.

## Escalation paths

Confirmed SQLi is rarely the deliverable on its own — it's the entry to something else. In order of impact:

1. **Read the auth tables.** `users`, `sessions`, `api_keys`, `oauth_tokens`, `password_reset_tokens` — every modern app has them under predictable names. Bcrypt hashes are still findings worth reporting because they're crackable offline.
2. **Pivot to admin.** Inject `OR 1=1` into a `WHERE user_id = ?` predicate inside an admin-check function. Often turns a low-priv account into full admin in one request.
3. **Read secret tables.** Look for `oauth_apps.client_secret`, `integrations.api_key`, `webhook_endpoints.secret` — these tend to map to live cross-system trust.
4. **Write to flags.** `UPDATE users SET is_admin=true WHERE id=$your_id` via injection into a UPDATE-shaped endpoint is the cleanest privesc.
5. **File primitives** (MySQL `INTO OUTFILE`, Postgres `COPY ... TO PROGRAM`, MSSQL `xp_cmdshell`) — these gate behind privileges that modern hosted DBs rarely grant, but on-prem stacks still allow them.

## What a real finding looks like

When you file the result, the report needs:

- The exact request that triggers the bug (curl-friendly, single-line)
- The exact response signature you keyed on (status, body length, ETag, a content snippet — whichever you used as the oracle)
- The detected DB and version
- A second request showing the predicate flipped (to prove control, not coincidence)
- One enumeration query you actually ran (e.g. `SELECT current_user()` result) — proves it's exploitable, not just "weird parser behavior"
- The query shape inferred from response patterns (e.g. "the handler runs `SELECT * FROM products WHERE active=1 AND name LIKE '%<input>%'`")
- A patch suggestion — usually "use parameterized queries; for identifier positions, validate against an allowlist"

## Common false positives

- **Generic 500s.** A 500 on `'` could mean the framework's error handler doesn't like single quotes in path params, not that the DB barfed. Confirm by reading the actual error text or by sending `\'` (escaped quote) — if THAT also 500s but `''` (doubled quote) doesn't, the framework is the issue, not SQL.
- **Static response sizes.** Some templating engines emit fixed-length responses regardless of input. A boolean diff that swings by ±0 bytes is not a real diff.
- **Caching layers.** Cloudflare / Fastly / Varnish in front of the app can return cached responses that look like body-stable predicates. Always send with `Cache-Control: no-cache` and a unique cachebuster on every request.
- **Async logging spikes.** `pg_sleep(0.5)` in a server already under load can look like noise. Use a 3-second baseline and require >2× separation before claiming a time-based hit.
- **Rate-limit-driven 429s** masquerading as filter-driven 403s — read the response body before deciding what blocked you.

## Related skills

`authentication_jwt` for chained pivots into session tokens, `idor` for what to do once you've exfiltrated user IDs, `business_logic` for SQLi that lives inside business workflows (refund manipulation, discount stacking).

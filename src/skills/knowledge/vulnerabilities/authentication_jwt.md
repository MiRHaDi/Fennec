---
slug: authentication-jwt
applies_to: [pentester, coder]
owasp: A07
related: [idor, business_logic, information_disclosure]
---

# Authentication & JWT — Pentester Playbook

> Load this when recon identified a JWT (header starts with `eyJ` followed
> by `.`), a custom session token, a login flow, password reset flow, or
> any OAuth/OIDC endpoint.

## When to load this

The targets where authentication bugs hide:

- Any `Authorization: Bearer eyJ…` header (that's a JWT)
- Cookie-set sessions that look base64-y (often JWT with `Cookie` transport)
- OAuth callback URLs (`?code=…&state=…`)
- Password reset flows (`/reset?token=…`)
- "Remember me" tokens
- API key generation / rotation endpoints
- MFA enrollment / step-up flows
- "Magic link" passwordless login

Anti-pattern fingerprints from recon that immediately raise the priority:

- JWT with `alg: HS256` AND the secret looks like an env var name or hostname (devs sometimes ship hostname-as-secret)
- JWT with `alg: none` (yes, this still appears in 2026)
- Password reset tokens that are short numeric codes
- Login endpoints with no rate limiting headers

## What you're looking for

Five distinct attack families. Identify which before testing:

- **Algorithm confusion.** Forge tokens by changing `alg` (`none`, switching HS256↔RS256).
- **Weak secret.** HS256 with a guessable secret — crack offline with `hashcat`/`john`.
- **Claim manipulation.** Token validates correctly but contains a forgeable claim (admin flag, tenant ID).
- **Flow-level.** OAuth state validation missing, password reset reuse, MFA bypass via parallel requests.
- **Token leakage.** Tokens in URLs, error messages, logs, third-party request headers (Referer leaks).

## First moves

1. **Decode the JWT.** Split on `.`, base64-decode each part. Look at the header (`alg`, `kid`, `jku`, `x5u`) and the payload (`sub`, `email`, `role`, `tenant_id`, `exp`, `iss`, `aud`). Don't crack anything yet — just read what's in there.

2. **`alg: none` probe.** Change `alg` in the header to `none`, drop the signature (leave the trailing `.` but make the third segment empty), submit. If the API accepts it, you have full forgery.

3. **HS256 with public key probe.** If the token is RS256, grab the public key (`/.well-known/jwks.json` if it's there, or any cert exposed). Re-sign the token with HS256 using the public key as the secret. Some libraries blindly trust the `alg` header and validate HS256 against any key they have on hand.

4. **Weak-secret crack.** For HS256: `hashcat -m 16500 token.jwt rockyou.txt` against the captured token. Modern hashcat with a GPU does the full rockyou wordlist in seconds. Cracks are surprisingly common — `secret`, `your-256-bit-secret`, the company name, app version strings.

5. **Claim swap.** Modify `role` to `admin`, `is_admin` to `true`, `tenant_id` to another tenant's value. Re-sign with the (cracked or none) algorithm. Submit. Any acceptance = privilege escalation.

6. **`kid` injection.** If the header has a `kid` (key ID), try injecting SQLi (`../../../etc/passwd`), path traversal, or directory traversal into the value. Some libraries dereference `kid` as a file path or DB key without sanitization.

7. **`jku` / `x5u` injection.** These headers point to a URL the library fetches for keys. If validated loosely (or not at all), point it at your own server and serve a key whose private half you control.

8. **No-expiry test.** Take a token with an `exp` claim, wait until it expires, and submit it. If accepted, expiration isn't enforced. Or: change `exp` to 5 years in the future and re-sign — if the library checks signature but not validity, "expired tokens" never expire.

## Confirming a hit

JWT forgery is binary: either the API accepts the forged token (you can call protected endpoints as the forged identity) or it rejects it. Confirm with:

- **Identity-bound endpoint.** Call `/api/me` or `/api/users/current` with the forged token. The response should show the identity from the forged claim — different email/ID/role than your real account.
- **Action-bound endpoint.** Try a privileged action only the forged identity could do (admin panel, another user's data). Success = forgery accepted by the authz layer too.

For non-JWT auth bugs:

- **Password reset reuse.** Use a reset token, then try to use it again. If it works the second time, tokens aren't single-use.
- **MFA bypass.** Login as user, get the MFA challenge, then call a protected endpoint without completing MFA — if the partial session works, MFA enforcement is incomplete.
- **OAuth state missing.** Trigger an OAuth flow with no `state` parameter. If the IdP completes anyway, you can chain to login CSRF.

## Going deeper — by mechanism

### JWT
- **Library-specific.** Each language has its quirks. `jsonwebtoken` (Node) had HS/RS confusion through 2017. PyJWT had `alg: none` acceptance up to v1.5. Java's `jose4j` had `kid` SQLi-able. Always check library version against published CVEs.
- **JWKS endpoint poisoning.** If the app caches JWKS, you might be able to inject your own key into the cache via cache key collision or response splitting against the JWKS fetcher.
- **Nested JWTs (JWE).** Encrypted JWT envelope around a signed JWT. Bypass via switching `alg` and `enc` in the outer header.
- **Embedded JWTs in cookies.** When the cookie isn't `HttpOnly`, XSS can steal it directly. When it is, watch for the JWT also being echoed in any unprotected response.

### Password reset
- **Token in URL leak.** Reset URLs in emails are often logged by the user's email provider, by analytics on subsequent navigation, by Referer headers to anything loaded on the reset page.
- **Account enumeration.** "If this email exists, we sent a reset link" vs "no account found" — most apps still leak existence somewhere (different response time, different error code under stress).
- **Race condition on consumption.** Submit the reset twice in parallel; some apps mark the token used after the password is set, so two parallel sets can race.
- **Email change after reset.** Reset → log in → change email immediately. Pair with a reset token from a leak (logs, screenshots) for full takeover.

### OAuth / OIDC
- **`state` missing/skipped/static.** Permits login CSRF (force victim to log in as attacker).
- **`redirect_uri` open or weak.** Wildcard subdomain on registered redirect = redirect to attacker page with the auth code.
- **`code` reuse.** Authorization codes should be single-use; many apps don't enforce.
- **PKCE downgrade.** Confidential clients that ALSO accept public-client flows can be downgraded to skip the client secret.
- **Token swap.** Some bugs let you swap an ID token from one client for an access token of another client, crossing trust boundaries.

### MFA
- **Brute force on TOTP.** 6-digit code = 1M possibilities, often no rate limit on the verification endpoint.
- **Backup codes never rotated.** Some apps issue backup codes once and never invalidate even after one is used.
- **MFA-bypass parallelism.** "Trust this device" flag, "remember for 30 days" cookie — sometimes settable client-side or via a different endpoint that skips MFA check.
- **MFA enrollment race.** If you can enroll an MFA factor before the victim does, you've added an additional auth factor under your control that doesn't lock them out (but does let you in).

## When filters get in the way

- **Signature validation enforces strict alg list.** Try unusual algs: `RS512`, `PS256`, `ES256K` — sometimes the validator's switch statement falls through.
- **JWKS endpoint is allowlisted.** Look for SSRF in the JWKS fetcher; chain SSRF to a host you control.
- **WAF blocks `alg: none`.** Try `alg: None`, `alg: NONE`, `alg: nOnE` — JSON is case-sensitive, parsers may not be.
- **Token entropy too high to brute force.** Skip cracking; pivot to algorithm confusion or claim manipulation paths.

## Escalation paths

1. **Account takeover.** Forge a token for a known victim user (`sub` claim) → call any endpoint as them.
2. **Privilege escalation.** Forge a token with `role: admin` or equivalent. Open every admin endpoint that was previously gated.
3. **Cross-tenant.** Change `tenant_id` claim to a different customer's tenant. Read their data.
4. **Persistent backdoor.** If you can mint tokens with arbitrarily long expiry, you have persistent access independent of the user's password.
5. **Pivot via service tokens.** Some apps use JWTs for internal service auth — forge a token claiming you're the billing service and call internal billing endpoints.

## What a real finding looks like

- The original captured token (decoded so the reviewer can see the claims)
- The forged token (with the modified claims shown clearly — `role: admin`, `sub: 999`, whatever)
- The request showing the forged token being accepted, with the response body proving you got data you shouldn't
- The library/version detected from response headers, error messages, or stack traces
- The fix: pin `alg` to a specific algorithm on the validator side, fetch JWKS from a hard-coded URL only, validate `iss`/`aud`/`exp`/`nbf` always, never trust `kid`/`jku` from the token itself

## Common false positives

- **`alg: none` accepted but no real privilege.** Some libraries decode but don't authenticate, then a separate authorization layer rejects the request. Confirm you can call a real protected endpoint, not just `/api/health`.
- **Cracked secret that doesn't grant access.** Some apps sign with one secret but validate with another (HMAC-only validation against a separate key). Forging works locally but the server rejects.
- **Replay of an unexpired token.** Reusing your own valid token isn't a finding — confirm you're using a forged or stolen one.
- **OAuth `state` echo without validation.** The IdP might echo `state` even if the relying party doesn't validate it. Confirm the RP actually trusts the value.

## Related skills

`idor` for what to do once you've forged your way into someone else's account, `business_logic` for multi-step bypasses (MFA enrollment races, OAuth flow manipulation), `information_disclosure` for the token-leakage source channels.

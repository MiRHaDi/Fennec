---
slug: broken-function-level-authorization
applies_to: [pentester]
owasp: A01
related: [idor, mass_assignment, authentication_jwt]
---

# Broken Function-Level Authorization — Pentester Playbook

> Load this when recon mapped both end-user endpoints and admin/internal
> endpoints, especially when the app has multiple roles. BFLA is the
> "vertical" sibling of IDOR — you can call a function you're not
> authorized for, regardless of which object ID is in the request.

## When to load this

The endpoints worth checking for BFLA:

- `/admin/*` paths discovered by gobuster but not linked from any UI you've seen
- Any endpoint with `delete`, `disable`, `reset`, `revoke`, `impersonate`, `migrate`, `export` in the name
- "Internal" / "debug" / "ops" / "support" prefixes
- Settings/config endpoints that affect the whole tenant
- Webhook management, API key generation, audit log viewers
- Bulk action endpoints (bulk delete, bulk export, mass update)
- Endpoints documented in OpenAPI/Swagger with role restrictions written in the description but not enforced server-side

The accounts you need:

- A low-privilege user (your "attacker") — basic role, minimal permissions
- A high-privilege user (your "victim") — admin or owner role — to know what privileged endpoints exist and what their normal request shape looks like

## What you're looking for

BFLA is about the *function* (verb + endpoint), not the *object* (ID parameter). The four canonical shapes:

- **Hidden admin endpoint, no auth check.** `/api/admin/users` returns the user list to anyone who knows the URL.
- **Documented admin endpoint, role check missing.** Endpoint expects `role=admin` on the JWT but the server just decodes the JWT and trusts whatever it says.
- **HTTP verb confusion.** `GET /api/users/123` is gated; `DELETE /api/users/123` isn't. Common when separate handlers were written and the auth decorator was applied to one but not all.
- **Endpoint-pair asymmetry.** `/api/users` (list) requires admin; `/api/users/search?q=*` (search) doesn't, and returns the same data.

## First moves

1. **Inventory privileged endpoints.** Log in as the high-privilege user. Use the UI to perform every admin action you can find — invite a user, change a setting, view billing, export data. Capture each request. Now you have your privileged-endpoint corpus.

2. **Replay as low-privilege user.** Take each captured admin request, swap in the low-priv user's auth header/cookie, send. Three outcomes per request:
   - **403/401** → endpoint is properly gated (good for them, no finding)
   - **200 with the action taking effect** → BFLA confirmed
   - **200 with an error envelope** (`{"error": "forbidden"}`) → check carefully; if the action ALSO didn't happen, it's gated; if it took effect anyway, it's still BFLA, just with a weird response

3. **Verb fuzzing on user-facing endpoints.** For each endpoint you can call as low-priv, try every verb: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD. Note any verb that returns a status other than `405 Method Not Allowed`. Each non-405 response is a separate function with potentially separate auth.

4. **Method override headers.** Some frameworks honor `X-HTTP-Method-Override` (or `_method` form field). Try sending `POST` with `X-HTTP-Method-Override: DELETE` — if the framework routes by override AND the auth check ran against the wire method (POST), you bypass.

5. **Unauthenticated admin probe.** Drop the auth header entirely. Hit every admin endpoint with no credentials. Some apps treat "no auth" as "default user" and apply default-user permission rules — sometimes those defaults include admin endpoints by mistake.

## Confirming a hit

BFLA confirmations:

- **Read-side.** Privileged data returned to the low-priv user. Show the response body containing fields the low-priv role shouldn't see (audit logs, other users' PII, system config).
- **Write-side.** The low-priv user performs an action that takes effect. Verify with a follow-up read AS THE HIGH-PRIV USER — log in as them and confirm the state changed.
- **Side-channel.** Some endpoints return 200 with no body but trigger an action (delete, send email, etc.). Confirm by checking the action's consequence: did the email arrive? Did the resource disappear?

## Going deeper — by enforcement style

### Decorator-based (Python/Flask/Django, Java/Spring)
Auth is applied with a decorator (`@admin_required`, `@PreAuthorize("hasRole('ADMIN')")`). Common bugs:
- Decorator forgotten on one endpoint among siblings
- Decorator applied to the view class but bypassed by the URL router's direct dispatch to a different method
- Decorator runs but inspects a parameter the request can control (`if request.user.role == request.params.get('expected_role')`)

### Middleware-based (Express, Rails, Go middlewares)
Auth runs as middleware before the handler. Common bugs:
- Path-prefix middleware (`/admin/*`) that misses `/admin` (no trailing slash) or `/admin/v2/*`
- Order-of-middleware bugs (auth runs after body parsing, body parser fails for malformed JSON, request gets to handler without auth check)

### Manual checks inside handlers
Auth check is the first few lines of the handler function. Common bugs:
- Missing entirely in some handlers
- Checks the wrong thing (`user.id` instead of `user.role`)
- Trusts a value from the request body (the request body says "I'm admin")

### Frontend-only enforcement
The "admin" button is hidden in the UI for non-admins but the endpoint behind it is unprotected. The bug exists; the only thing missing is for someone to discover the endpoint URL. Gobuster + JS file analysis finds these reliably.

## When filters get in the way

- **Path normalization differences.** `/admin/users` blocked but `/admin//users`, `/admin/./users`, `/admin/x/../users`, `/Admin/users` (case), or URL-encoded variants (`/admin%2fusers`) work. The auth middleware ran before normalization, the router ran after.
- **HTTP/1.1 vs HTTP/2.** Some WAFs and reverse proxies enforce auth on HTTP/1.1 requests differently from HTTP/2. Burp's HTTP/2 toggle is a one-click test.
- **Trailing slash sensitivity.** `/admin/users/` allowed, `/admin/users` blocked (or vice versa).
- **Header injection.** Some apps trust `X-Forwarded-For`/`X-Real-IP` to identify "internal" callers and skip auth for "internal" requests. Send `X-Forwarded-For: 127.0.0.1`.
- **Host header.** Some apps run separate auth chains for `admin.example.com` vs `app.example.com` — if both Host headers resolve to the same server, the wrong chain might apply.

## Escalation paths

1. **User enumeration.** Admin endpoint that lists all users → enumerate the customer base.
2. **Password reset trigger.** Admin endpoint that resets passwords → "reset" a victim's password to a value you choose.
3. **Impersonation.** Admin endpoint that switches the session to "view as user X" → become any user.
4. **Tenant escape.** Admin endpoint scoped to the wrong tenant → cross-tenant pivot.
5. **Settings tampering.** Disable MFA org-wide, allowlist an attacker IP, add an SSO provider you control — long-term backdoor.

## What a real finding looks like

- The privileged endpoint URL + the verb
- The request from the low-priv user (auth header, body)
- The response showing the action succeeded or the data leaked
- Confirmation as the high-priv user that the state changed (for write-side findings)
- The role / permission of the low-priv user clearly stated — "viewer" or "guest" or "free-tier user"
- The fix: enforce role checks server-side as middleware, NOT in the UI; for each handler, the security default should be deny-all + explicit role allowlist

## Common false positives

- **403 with a 200 status.** Some apps respond `200 OK` with an error body — read the body. If the action didn't take effect AND the response says "forbidden," it's gated, just with a non-standard status.
- **Endpoint accessible but data filtered.** `/api/admin/users` returns 200 with empty array because the server filters by your role's visibility scope. Not BFLA — the filter is the authorization.
- **Endpoint that looks privileged but isn't.** `/admin/profile` might just be "the profile page within the admin UI" but functionally identical to `/profile`. Read the actual response — if it's the same data the user already has access to, no privesc.
- **Cached responses.** Sometimes a 200 you see is a CDN cache from a previous admin's request. Send with `Cache-Control: no-cache` and a unique cachebuster to confirm.

## Related skills

`idor` for the horizontal (cross-user) sibling, `mass_assignment` for the "I can flip my role to admin via body parameter" attack, `authentication_jwt` for the case where the auth check trusts a forgeable claim.

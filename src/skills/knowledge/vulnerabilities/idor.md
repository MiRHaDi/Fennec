---
slug: idor
applies_to: [pentester]
owasp: A01
related: [broken_function_level_authorization, business_logic, mass_assignment]
---

# Insecure Direct Object Reference — Pentester Playbook

> Load this when recon mapped any REST/GraphQL endpoint that includes an
> object identifier in the path, query, or body — `/users/123`,
> `/orders/{id}`, `/api/projects/abc?file=def`, etc. IDOR is the single
> highest-prevalence vuln class against modern API-driven apps.

## When to load this

The default assumption against any API: every parameterized object endpoint is IDOR until proven otherwise. Specific hotspots:

- Numeric IDs in URLs (`/users/4521`) — easiest to enumerate
- UUIDs that turn out to be sequential or guessable (CockroachDB UUIDs leak timestamps; ULIDs are intentionally ordered)
- Filename/path references in download/preview endpoints
- "Switch to view as" or "impersonate user" features
- Shopping cart, order, invoice IDs
- Account-scoped resources accessed via tenant ID in the URL
- Webhook IDs, API key IDs, integration IDs — often the same ID space across tenants
- Anything with a `userId=` or `accountId=` parameter — sometimes that's not authorization, it's filtering

## What you're looking for

IDOR isn't one bug — it's the absence of one specific authorization check. The four shapes:

- **Direct unauthenticated.** `/users/123` returns 123's data with no auth at all. Rare in mature apps.
- **Authenticated horizontal.** Logged in as user A, you can access user B's resources (same role, different tenant). Most common case.
- **Authenticated vertical.** Logged in as a regular user, you can access admin endpoints by knowing the URL. Often pairs with `broken_function_level_authorization`.
- **Hidden parameter / parameter injection.** Sending `?user_id=B` overrides the session's implicit user. Especially common in legacy APIs where the same endpoint is used by both end-user and admin UIs.

## First moves

You need **two accounts in the same tenant tier** for the cleanest testing — one as the "attacker" (user A), one as the "victim" (user B). If only one account is available, you can still hunt unauthenticated IDOR and parameter-injection patterns, but the strongest findings need cross-account proof.

1. **Object inventory.** From recon, list every endpoint that takes an ID. For each, note the ID shape (integer, UUID, slug, hash) — guessability matters for severity.

2. **Round-trip baseline.** As user A, perform a normal action (view profile, list orders, download a file) and capture the request. Now you have a template.

3. **Cross-account swap.** Replace A's ID with B's ID in each spot you can find — path segment, query param, header, JSON body field. Each swap is a separate hypothesis. Send each one, check the response:
   - 200 with B's data = IDOR confirmed
   - 200 with A's data (ID ignored) = filter-only-by-session, not vulnerable
   - 403/404 = authorization is enforced
   - 500 = inconsistent — flag for investigation, often indicates a partial check

4. **Sequential ID probe.** If IDs are numeric, decrement/increment by 1 and try ±100, ±1000. A handful of sequential probes is enough to confirm "any ID works" without making 10,000 requests.

5. **HTTP verb swap.** An endpoint that's read-only (`GET`) may have a sibling write endpoint (`PUT`, `DELETE`) without the same auth check. Try all five verbs against each endpoint.

6. **Hidden parameter sniff.** Send the same request but add `?user_id=B`, `?account_id=B`, `?tenant_id=B`, `?customer_id=B`. Some APIs respect explicit overrides because internal callers use the same endpoint.

## Confirming a hit

The cleanest IDOR confirmation: two screenshots of the same endpoint returning two different users' data, with the only difference being the ID in the request. Specifically:

- **Direct read confirmation.** As A, fetch B's resource by swapping the ID. The response body should contain B's identifying fields — email, name, account number, things that prove it's B's data not A's.
- **Write confirmation.** As A, PUT/PATCH/DELETE B's resource and then read it back (as A or as B) to prove the change took effect.
- **Listing leak.** Some IDOR is in list endpoints — `/api/users?account_id=B` returns all users in B's account because the filter parameter isn't validated against the session.

Always confirm with the actual victim user as well: log in as B, view their own data, and prove that what A saw matches what B sees. Rules out the "you saw a cached or stub response" objection.

## Going deeper — by ID type

**Integer IDs.** Enumerable by definition. Severity is "every user's data" unless rate-limited. Test enumeration depth: try the lowest valid ID (often 1 = the founder's account), the highest, and a sample in the middle. Note response time per request — IDs that don't exist often respond faster.

**UUIDs.** Believed unguessable, often aren't:
- UUIDv1 includes a timestamp + MAC address — predictable if you know an account creation time
- UUIDv4 is properly random, but the *generation* might be deterministic (some apps seed RNG from request data)
- Sequential bulk imports leak UUIDs in admin exports, logs, error messages — any leak source = enumeration without brute force
- Look for UUIDs in the body of other requests (shared between users, embedded in webhook events, etc.)

**Slugs.** `/projects/my-cool-project` — guessable by social engineering (Twitter handles, company names) but generally low-volume enumeration. The IDOR is still real if authorization isn't checked.

**Encoded references.** Base64 of `(user_id, resource_id, timestamp)` — often decodable, often forgeable. Decode any opaque token you see; if it contains structured data, treat it as a numeric ID.

**Hash-based IDs.** `sha1(user_id + secret)` is unguessable but might leak in logs, URL bars, screenshots. Also: if the secret is short or shared across tenants, brute force is on the table.

## When filters get in the way

- **Strict format validation.** API insists on UUIDs only. Bypass with another user's actual UUID (extracted from any source — share links, public profiles, integration webhooks).
- **Permission preflight.** Some APIs do a permission check on a `GET /api/permissions/can_view/:id` then trust the result client-side. Skip the preflight and call the real endpoint directly.
- **JWT-bound IDs.** The user ID is inside the JWT, not the URL. Mass-assignment-style: send a request body that overrides the JWT-derived field. Or attack the JWT itself (see `authentication_jwt` skill).
- **GraphQL-specific.** GraphQL queries often embed IDs in nested object selections. Swap any ID in the query — `query { user(id: "B") { email, posts { id, body } } }`.

## Escalation paths

IDOR by itself is usually a critical finding. To make it worse:

1. **Cross-tenant.** Same bug works across companies, not just across users within one company. Multiply severity by every tenant on the platform.
2. **Account takeover.** IDOR on `PUT /users/:id` lets you change another user's email → password reset to your inbox → login as them.
3. **Privilege escalation.** IDOR on `PUT /memberships/:id` to make yourself admin of someone else's account.
4. **Financial impact.** IDOR on order/billing endpoints — read or modify other users' orders, refunds, payment methods.
5. **PII / regulatory.** Mass enumeration of users gives a GDPR/CCPA notification trigger. Read in the finding: "an attacker could iterate all N users in M minutes."

## What a real finding looks like

- Two requests side by side: one with your own ID (returns your data, control case) and one with the victim ID (returns victim data, IDOR case)
- The request templates as curl, ready to paste — including the auth header
- A short note on how the victim ID was obtained (sequential enumeration, exposed in another response, social engineering — be explicit, severity depends on this)
- The set of related endpoints that share the bug — if `/users/:id` is broken, `/users/:id/orders` and `/users/:id/messages` are probably broken too. Don't make the developer go hunting for siblings.
- The exact field check that's missing — "endpoint should compare `session.user_id` to `path.user_id` before returning"

## Common false positives

- **Both users return identical data.** Some endpoints return tenant-global data (feature flags, plan limits) intentionally. If A and B see the same thing because the data isn't user-scoped, no IDOR.
- **403 that looks like 200.** Some APIs respond with 200 + an error envelope (`{"error": "forbidden"}`). Read the body, not just the status.
- **Session-bound endpoints that ignore the URL ID.** `/users/:id/profile` that always returns the session user's profile regardless of `:id`. The URL parameter is decoration, not authorization input. Not an IDOR.
- **Public profile endpoints.** Some endpoints are public by design (`/users/:username/public-profile`). Confirm the data returned is actually public-tier info, not private.

## Related skills

`broken_function_level_authorization` for vertical privesc (admin endpoints), `business_logic` for IDOR that lives inside multi-step workflows (refunds, transfers), `mass_assignment` for the parameter-override variants.

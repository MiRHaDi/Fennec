---
slug: fastapi
applies_to: [pentester, coder]
related: [authentication_jwt, mass_assignment, ssrf]
---

# FastAPI — Pentester Playbook

> Load this when recon fingerprinted FastAPI (via `/docs`, `/redoc`,
> `/openapi.json`, the FastAPI response headers, or 422 validation errors
> with the distinctive `{"detail": [{"loc": [...], "msg": "..."}]}`
> shape).

## When to load this

Identifying signals from recon:

- `GET /docs` returns the Swagger UI
- `GET /redoc` returns the ReDoc UI
- `GET /openapi.json` returns the full OpenAPI spec — read this first; it's the entire attack surface
- 422 errors with `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}` are the FastAPI default
- `server: uvicorn` header (FastAPI's default ASGI server)

## What you're looking for

FastAPI's design pushes most security decisions to the developer. The framework provides good defaults for input validation and serialization, but auth, ownership checks, and rate limits are entirely the dev's job. Common bug-shapes:

- **OpenAPI exposed in production.** `/docs` and `/openapi.json` are on by default. Many teams forget to disable.
- **Pydantic mass assignment.** A request body is parsed into a Pydantic model that includes server-side fields.
- **Dependency injection auth gap.** `Depends(get_current_user)` returns None when no token is sent, and the handler forgets to check.
- **CORS too permissive.** `allow_origins=["*"]` plus `allow_credentials=True` — the combination is silently ignored by Starlette but reveals dev intent.
- **`Form` vs `Body` confusion.** Same endpoint accepts both, with different validation.

## First moves

1. **Pull the OpenAPI spec.** `curl https://target/openapi.json | jq` — you now have every route, every method, every parameter, every response schema. This is the entire surface.

2. **Inventory undocumented routes.** From `openapi.json`, list every `path`. Many of these aren't in the public UI — admin endpoints, debug routes, internal-use paths. Test each.

3. **Check `/docs` and `/redoc`.** Both default to enabled. If reachable in production, this is at minimum an `information_disclosure` finding (reveals API surface to anyone).

4. **Parse the schemas.** For each endpoint's request body schema, look for fields that probably shouldn't be client-settable: `id`, `created_at`, `updated_at`, `user_id`, `is_admin`, `verified`, `role`. Send a request setting each.

5. **Auth probe.** For each endpoint, drop the auth header and resubmit. FastAPI's default `Depends(oauth2_scheme)` returns None when no token is sent unless you use `Depends(oauth2_scheme(auto_error=True))`. Endpoints that take `current_user = Depends(...)` but never check `if not current_user` are unauthed.

6. **Pydantic validation bypass.** Try sending fields of the wrong type:
   - Field declared `EmailStr` → send a non-email string (sometimes valid because of Pydantic v1 vs v2 differences)
   - Field declared as `int` → send a string that looks like an int (`"123"`); Pydantic coerces by default
   - Field declared `Optional[X]` → send `null` explicitly
   - Nested model required → send empty dict `{}`

7. **OPTIONS / CORS probe.** Send OPTIONS preflight from `Origin: https://evil.com` and read the response. `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` is the misconfiguration sweet spot.

## Confirming a hit

- **Schema mass assignment.** Send the extra field, then GET the resource. The new value should be in the response.
- **Unauth endpoint.** Drop the auth header and confirm 200 response with user-specific data.
- **OpenAPI leak.** Show the OpenAPI fetch + a list of endpoints not in any UI but reachable.
- **CORS misconfig.** Show the OPTIONS preflight + the simple-request that follows succeeding from a different origin.

## Going deeper — FastAPI-specific patterns

### Dependency injection auth gaps
The FastAPI pattern:
```python
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = decode_token(token)
    return user  # returns None if token is bad/missing
```
If the handler is:
```python
@router.get("/items/")
def list_items(user = Depends(get_current_user)):
    return Items.all_for(user)
```
And `Items.all_for(None)` returns the global list, you have unauth access. Always test endpoints with no auth and check that responses are properly empty / 401.

### Path operation dependencies
FastAPI lets you put dependencies as decorators (`@router.get("/x", dependencies=[Depends(verify_admin)])`). These run for side-effects only — if `verify_admin` returns silently on non-admin (instead of raising), the endpoint is open to non-admins. Look at the dependency's source for any non-raising path.

### Pydantic v1 vs v2 behavioral differences
- v1: `validator` decorators; field validation is permissive on coercion
- v2: `field_validator`/`model_validator`; stricter coercion, different error messages

Migrations are common bug sources — handlers ported from v1 to v2 sometimes lose validation behavior silently.

### `Body(embed=True)` vs `Body()` confusion
```python
@router.post("/x")
def x(item: Item = Body(embed=True)):  # expects {"item": {...}}
def x(item: Item):                     # expects {...} directly
```
Same handler, different body shapes. Sending the wrong shape sometimes results in 200 with a silently-empty model (all fields None) — combined with mass assignment patterns, this can let you bypass validation.

### `response_model` exclusion bypass
`@router.get("/users/me", response_model=UserPublic)` filters the response to `UserPublic` fields. But if the handler returns raw dicts (not the model), the filter doesn't apply — internal fields leak.

### Background tasks
`BackgroundTasks` queues work to run after the response is sent. If the auth check is inside the background task, the response is delivered first (with success), then the task runs and might fail silently. The user gets a 200 even though nothing happened.

### WebSocket auth
FastAPI WebSocket endpoints don't auto-apply HTTP dependencies. `@router.websocket("/ws")` with `current_user = Depends(get_current_user)` doesn't work — you need to read the token from the WS handshake explicitly. Many devs miss this; WebSocket endpoints are unauthed.

### Starlette middleware order
Middleware applies in reverse-declaration order. If CORS middleware is added before auth middleware, CORS preflight succeeds without auth. Usually fine, but if CORS allows credentials AND auth runs after CORS, browsers can attempt cross-origin authenticated requests against endpoints that should reject pre-auth.

## When filters get in the way

- **Pydantic field types are strict.** Send the right type, then test logic bugs at the validation boundary (negative numbers, empty strings, deeply nested objects).
- **`auto_error=True` in oauth2_scheme.** This raises 401 on missing tokens. Try sending malformed but-present tokens to differentiate handlers that validate vs handlers that just decode.
- **Rate limiting via slowapi.** Common addition. Check whether it's per-IP (bypassable via X-Forwarded-For if behind a proxy) or per-token (bypassable by rotating tokens).

## Escalation paths

1. **OpenAPI leak → enumerate admin endpoints not in UI → BFLA testing on each.**
2. **Mass assignment via Pydantic → role flip / cross-tenant.**
3. **Unauth WebSocket → subscribe to other users' real-time updates.**
4. **CORS misconfig → cross-origin token theft.**
5. **Permissive `Depends` → run admin-only logic as a regular user.**

## What a real finding looks like

- The OpenAPI fragment showing the vulnerable endpoint
- The request showing the bug (mass assignment, unauth, CORS, etc.)
- A note on which FastAPI/Starlette version was detected (matters for known CVEs)
- The fix specific to the bug: separate request/response Pydantic models, dependency that raises on missing user, explicit CORS origin list

## Common false positives

- **422 validation errors that look like exploitable type confusion.** FastAPI's validation is generally tight; if you got a 422, the framework caught your bad input. Real bugs usually return 200.
- **`/docs` exposed but auth-gated.** Some teams require auth on `/docs` itself — check before reporting OpenAPI leak.
- **OpenAPI spec missing the admin routes.** FastAPI includes routes in OpenAPI by default. If admin routes are missing from `openapi.json`, the dev probably added `include_in_schema=False` — they exist but aren't documented. Still need to test them; gobuster the path.

## Related skills

`authentication_jwt` for the bearer-token handling FastAPI typically uses, `mass_assignment` for the Pydantic model-bind shape, `ssrf` for any URL-taking endpoints FastAPI commonly exposes for webhooks.

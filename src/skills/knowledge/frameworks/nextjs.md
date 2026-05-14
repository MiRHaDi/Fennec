---
slug: nextjs
applies_to: [pentester, coder]
related: [ssrf, idor, information_disclosure]
---

# Next.js — Pentester Playbook

> Load this when recon fingerprinted Next.js — the `_next/` static asset
> path, the `x-powered-by: Next.js` header, RSC streaming responses, or
> `__NEXT_DATA__` script tag in the HTML source.

## When to load this

Recon signals for Next.js:

- `GET /_next/static/...` returns JS/CSS bundles
- `GET /_next/data/<buildId>/<page>.json` returns prebuilt page data
- `<script id="__NEXT_DATA__" type="application/json">` in HTML
- `X-Powered-By: Next.js` header (not always set)
- Server Components: HTML response includes RSC payload chunks (`<script>self.__next_f.push(...)</script>`)
- App Router vs Pages Router — both can coexist; check both `/api/*` and `/app/*` paths

The Next.js version matters a lot — Next 13.4 introduced App Router and Server Actions, which have their own bug shapes.

## What you're looking for

Next.js bundles a lot of behavior into the framework; many of the bugs are framework-specific rather than generic web vulns:

- **Middleware bypass.** The `middleware.ts` matcher misses paths the dev expected to cover.
- **API route auth gap.** `app/api/*/route.ts` handlers without auth checks (Next doesn't enforce any default).
- **Server Action over-permission.** A function annotated with `"use server"` can be called from any browser, not just from the component that imports it.
- **`getServerSideProps` leaking secrets.** Returning entire model objects without filtering.
- **Image optimization SSRF.** The `/_next/image` endpoint fetches arbitrary URLs by design.
- **Build-time data leakage.** Pages prerendered with sensitive data exposed in `_next/data/...json`.
- **CVE-2025-29927 (middleware auth bypass).** Send `x-middleware-subrequest: middleware:middleware:...` (repeated) to bypass middleware entirely — patched but still found unpatched in the wild.

## First moves

1. **Identify routing model.** Pull `index.html` from the homepage and look at `<script id="__NEXT_DATA__">`. `props.pageProps` indicates Pages Router; `props` containing `RSC` chunks indicates App Router. Many real apps have both.

2. **Enumerate API routes.** Common patterns:
   - Pages Router: `/api/...`
   - App Router: `/api/.../route.ts` (same URL pattern; you can't tell from outside)
   
   Gobuster against `/api/` with a wordlist. Also pull every `_next/static/chunks/*.js` and grep for `"/api/"` patterns — JS bundles often reveal API routes not linked anywhere.

3. **`_next/data` enumeration.** For each known route, hit `/_next/data/<buildId>/<route>.json`. The buildId is in `__NEXT_DATA__.buildId`. These JSON responses often contain MORE data than the rendered HTML (because the HTML filters/transforms what's shown, but the data fetcher returned the whole object).

4. **Middleware bypass probe (CVE-2025-29927).** Send a request to a middleware-protected route with header `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware`. On unpatched Next.js, this bypasses middleware entirely. Patched in 13.5.9, 14.2.25, 15.2.3.

5. **Server Action enumeration.** App Router apps use Server Actions. Look at the HTML source for elements with `formAction="..."` or `action="..."` pointing to randomized strings — these are the action IDs. Each is callable directly via POST.

6. **Image optimization SSRF.** `/_next/image?url=http://OAST_HOST/probe&w=128&q=75`. By default, Next blocks arbitrary URLs unless they're in `next.config.js` `images.domains`. But: many configs whitelist the app's own domain, and the app might have its own SSRF.

7. **API debug probe.** Try `/api/__debug__`, `/api/healthcheck`, `/api/preview`. Preview mode is a Next.js feature for unpublished CMS content — if exposed without auth, attackers can preview anything.

## Confirming a hit

- **Middleware bypass.** Show two requests — one without the header (302 to login), one with the header (200 with protected content).
- **Data leak in `_next/data`.** Compare the rendered HTML field count vs the JSON response field count. Show fields that exist only in JSON.
- **Unauth Server Action.** POST the action ID with a constructed body, confirm the action executed.
- **Image SSRF.** OAST callback proves the fetch happened.

## Going deeper — Next.js specific patterns

### Server Actions
A Server Action is a function with `"use server"` annotation. It compiles into a hidden POST endpoint. The endpoint accepts:
```
POST /<page-route>
Content-Type: multipart/form-data
Next-Action: <action-id>
Body: ... (action arguments)
```

- The action ID is a hash visible in the rendered HTML
- Actions don't auto-check the caller's identity or which page is invoking them
- An action defined in `/admin/page.tsx` is callable from `/public/page.tsx` if you know the action ID
- Always test each action with: no auth, low-priv auth, and from a different page than where it was originally rendered

### React Server Components (RSC)
RSC payloads stream as `<script>self.__next_f.push([1, "..."])</script>`. The string content is the serialized component tree. Decode the chunks for:
- Server-only props that leaked into the serialized payload (rare but happens)
- API route paths that get called during render
- Hardcoded URLs / endpoints visible in the streamed output

### `getServerSideProps` / `getStaticProps` (Pages Router)
These functions run server-side and return props. Common bugs:
- Returning the entire DB model: `return { props: { user: await db.user.find(id) } }` — every field of `user` ends up in `__NEXT_DATA__` JSON, accessible to client-side JS regardless of what the page renders
- Sensitive `process.env` values referenced in `getServerSideProps` returning into props
- Error messages from DB queries leaking into props on the error path

### API Route handlers (App Router)
```ts
// app/api/users/[id]/route.ts
export async function GET(req, { params }) {
  return Response.json(await db.user.find(params.id))
}
```
This has no auth, no validation, no ownership check. If the dev didn't add one, IDOR is guaranteed.

### Middleware matcher quirks
```ts
export const config = { matcher: ["/admin/:path*"] }
```
- Matches `/admin/x`, `/admin/x/y` — but NOT `/admin` (no trailing path). Test the bare base path.
- Doesn't run on `/_next/*` paths (excluded by default)
- Doesn't run on `/api/*` if matcher excludes it (often a mistake)
- Case-sensitive

### Edge runtime vs Node runtime
Middleware runs on Edge (no Node APIs, limited libraries). API routes default to Node but can opt into Edge. Some auth libraries don't work on Edge (e.g., libs that require crypto or Node streams). If an auth check fails silently on Edge, the request proceeds without auth.

### Built-in image optimization SSRF
`/_next/image?url=...` — by default restricted by `images.domains` / `images.remotePatterns` config. If `domains: ["*.target.com"]`, the optimizer fetches any subdomain of target.com — which combined with subdomain takeover or open redirect gives you cloud-metadata access.

### `next/headers` and `cookies()` server-side
RSC components can read cookies and headers server-side. Bug shape: a component reads a cookie to determine privilege, but the component is rendered into RSC and cached at build time — the privilege check ends up baked into the static output, applied to all users.

### Build artifacts in `.next/`
Some misconfigurations expose the entire `.next/` directory. `.next/BUILD_ID`, `.next/server/pages-manifest.json`, `.next/static/...` — full enumeration of routes and JS bundles. Some setups also expose `.next/server/app/...` which can include compiled server code.

### `next.config.js` `rewrites`/`redirects`
- `source: "/admin/:path*", destination: "/api/admin/:path*"` — rewrites can leak the internal API path used.
- Rewrites can introduce open-redirect-style issues if the destination accepts arbitrary input.
- `permanentRedirect` 308s vs temporary 307s — behavior on method preservation differs.

## When filters get in the way

- **Middleware enforces auth.** Test the CVE-2025-29927 bypass. Also test if middleware can be bypassed via case differences (`/Admin/...`), trailing slashes, or via `/api/...` if matcher excludes it.
- **Next/Auth (NextAuth.js / Auth.js).** Common auth lib. Test JWT-based auth bypass patterns, session token forgery, CSRF on auth endpoints (NextAuth has historically been weak on CSRF for some flows).
- **API routes with `next-connect` style guards.** Each handler is its own middleware chain. Test whether the guards apply to all verbs (GET protected, POST not).

## Escalation paths

1. **CVE-2025-29927 → access admin pages.**
2. **Server Action from non-owner page → privilege escalation.**
3. **`_next/data` JSON leak → mass data exfiltration.**
4. **Image SSRF → cloud metadata.**
5. **API route IDOR → full user enumeration.**

## What a real finding looks like

- The Next.js version detected (matters hugely for known CVEs)
- The route pattern (App Router vs Pages Router) and the relevant file path the bug lives in
- The exact request that triggers it
- A note on Vercel vs self-hosted (some bugs only apply in one deployment)
- The fix specific to the Next pattern: middleware fix, action ownership check, response filtering, image config

## Common false positives

- **`_next/data` JSON identical to rendered HTML.** Some apps already filter at the data layer. Not a leak.
- **API route returns 401 from the Next default.** Next doesn't return 401 by default — if you got one, the dev added auth. Confirm by checking if you can bypass.
- **Image endpoint blocked by config.** If `images.domains` is properly restricted, the SSRF is bounded. Note as hardening recommendation rather than vulnerability.
- **Middleware doesn't apply to `/api/auth/*`.** NextAuth.js routes are excluded by default; that's by design.

## Related skills

`ssrf` for the image-optimization and webhook-fetcher angles, `idor` for the API route ownership gaps, `information_disclosure` for the `_next/data` and build artifact angles.

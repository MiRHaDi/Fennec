---
slug: supabase
applies_to: [pentester, coder]
related: [sql_injection, idor, information_disclosure]
---

# Supabase — Pentester Playbook

> Load this when recon found Supabase — calls to `*.supabase.co`,
> Supabase SDK in JS bundles, the `apikey` header in requests, or
> Supabase auth tokens (`sbat_*` / `sb-*` cookies).

## When to load this

Recon signals:

- HTTP requests to `https://<project>.supabase.co/rest/v1/...` (PostgREST)
- `https://<project>.supabase.co/auth/v1/...` (Supabase Auth, GoTrue under the hood)
- `https://<project>.supabase.co/storage/v1/...` (Storage)
- `https://<project>.supabase.co/functions/v1/...` (Edge Functions)
- `https://<project>.supabase.co/realtime/v1/...` (Realtime subscriptions)
- `apikey:` header in requests with a JWT-like value
- `@supabase/supabase-js` package in JS bundles

Supabase is essentially "Firebase but on Postgres." The attack surface is similar but the security model is different: Row Level Security (RLS) policies on Postgres tables instead of Firestore rules.

## What you're looking for

Five characteristic bug shapes:

- **RLS disabled.** Table has no `ENABLE ROW LEVEL SECURITY` — anyone with the `anon` key can read/write everything in the table.
- **Permissive RLS policy.** `USING (true)` or `USING (auth.role() = 'authenticated')` — effectively no protection.
- **Service-role key leaked.** The `service_role` key bypasses RLS entirely. If leaked client-side (JS bundle, env vars in responses), full DB compromise.
- **Storage bucket public.** Bucket policy allows public read/write without auth or with permissive RLS.
- **Edge Function auth gap.** Edge Functions don't auto-verify JWTs; dev has to manually check.

## First moves

1. **Extract the project ref and anon key.** From the app's JS:
   ```js
   const supabase = createClient(
     "https://abcdefghij.supabase.co",
     "eyJhbGciOiJIUzI1NiIs..."  // anon key (JWT)
   )
   ```
   The anon key is intended to be public; the bug is whether RLS protects what it grants access to.

2. **Decode the anon key.** It's a JWT. Decode it to see the `role` claim (usually `anon`) and the `ref` (project ID). Confirm you're targeting the right project.

3. **Enumerate tables.** PostgREST exposes every table as a REST endpoint:
   ```
   GET https://<ref>.supabase.co/rest/v1/<table_name>?select=*
   Headers: apikey: <anon_key>, Authorization: Bearer <anon_key>
   ```
   You don't know table names from the URL alone — read the JS bundle for `from("table_name")` patterns. Or guess common ones: `users`, `profiles`, `posts`, `comments`, `orders`, `messages`, `subscriptions`.

4. **Unauth probe.** For each table, send the GET above with no Authorization header (or with the anon key as both `apikey` and `Authorization`). If you get data back, RLS is either disabled or trivially permissive.

5. **Authed probe.** Sign up via the Auth API:
   ```
   POST https://<ref>.supabase.co/auth/v1/signup
   {"email": "test@example.com", "password": "..."}
   ```
   Get a token back. Use it as the Bearer token in subsequent requests. Re-probe everything — now you're an authenticated user.

6. **Cross-user probe.** With your authed token, try to read rows that belong to other users. Most apps use a `user_id` column; query with filters: `?user_id=eq.<other-uid>`. If RLS isn't user-scoped, you can read everything.

7. **Insert probe.** Try inserting a row with `user_id` set to another user:
   ```
   POST https://<ref>.supabase.co/rest/v1/<table>
   Content-Type: application/json
   {"user_id": "OTHER_UID", "content": "..."}
   ```
   If accepted, you can plant rows on other users' behalf.

8. **Service-role key search.** Grep JS bundles, source maps, exposed `.env` files for the service-role JWT pattern (`role: service_role` in the decoded JWT). If you find one, the project is fully compromised.

## Confirming a hit

- **RLS disabled.** Show the GET returning data without auth (anon key only, no Bearer).
- **Cross-user read.** Show two responses — one with your own user_id filter (your data), one with another user's filter (their data). Both 200.
- **Cross-user write.** POST that creates a row attributed to another user, then GET that confirms the row exists.
- **Service-role leak.** Show the decoded JWT with `role: service_role`. Don't actually use it for destructive ops without authorization.

## Going deeper — by surface

### Row Level Security policies
RLS lives in Postgres. Policies look like:
```sql
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own messages"
  ON messages FOR SELECT
  USING (auth.uid() = user_id);
```

Common bugs:
- `ENABLE ROW LEVEL SECURITY` forgotten. Default is permissive — without RLS enabled, the anon role can read everything.
- Policy applies to SELECT only, not INSERT/UPDATE/DELETE. Test all four operations per table.
- Policy uses `auth.role() = 'authenticated'` only — every signed-up user passes, including bad actors who just signed up.
- Policy checks `auth.uid() = user_id` in USING but not in WITH CHECK (the latter applies to INSERT/UPDATE writes); attacker can create rows with arbitrary `user_id`.
- `USING (true)` for some "view" tables that turn out to contain sensitive data.

### PostgREST query parameters
PostgREST exposes Postgres operators:
- `?id=eq.5` (equal), `?id=in.(1,2,3)`, `?id=gt.5` (greater than), `?name=ilike.*admin*` (case-insensitive LIKE)
- `?select=*` for full record
- `?select=id,email,users:user_id(name)` for joins (relational queries)
- `?order=created_at.desc.nullslast`
- `?limit=1000` — defaults to limit defined in config, often 1000

The relational query feature is dangerous: `?select=id,private_table:user_id(*)` joins to other tables. If the joined table has weak RLS, you can pull data via the join even if the main table is protected.

### Auth (GoTrue)
- **Signup with arbitrary email.** Many setups allow signup without email verification. Attacker creates account, completes flows that require any authenticated user.
- **Phone signup.** SMS-based, costs the project money. Susceptible to SMS bombing.
- **Magic-link reuse.** Magic links should be single-use; some configs allow reuse.
- **Password reset enumeration.** Different responses for valid vs invalid emails.
- **`raw_user_meta_data` / `user_metadata`.** Client-settable in some flows; if RLS or app code trusts these, you can self-promote.
- **JWT secret.** The HS256 secret is on Supabase's side, not exposable. But: misconfigurations sometimes expose the secret via project settings or env leaks. With it, you mint admin tokens.

### Storage
- **Public buckets.** Visible at `https://<ref>.supabase.co/storage/v1/object/public/<bucket>/<file>`. List via `https://<ref>.supabase.co/storage/v1/object/list/<bucket>` if listing isn't restricted.
- **Signed URL TTL.** Some apps generate signed URLs with very long expirations — anyone who sees the URL once has long-lived access.
- **Bucket RLS.** Storage objects can also have RLS policies. Same patterns as table RLS.

### Edge Functions
- **No default auth.** Functions receive a `req` object. The dev has to call `supabaseClient.auth.getUser(token)` to verify. Many skip this.
- **Service-role key in env.** Functions often have `SUPABASE_SERVICE_ROLE_KEY` in env. If the function takes user input that ends up in a query using this key, RLS is bypassed.
- **CORS misconfig.** Functions return their own CORS headers. Permissive defaults are common.

### Realtime subscriptions
- **WebSocket-based.** Connects to `wss://<ref>.supabase.co/realtime/v1/websocket?apikey=<anon_key>`.
- **Auth via JWT.** Sends auth message after connect; if not sent, defaults to anon role.
- **RLS applies to realtime too.** Same bugs as REST — subscribing to a table you shouldn't see.
- **Broadcast / Presence channels.** Custom channels; often unauth by default.

## When filters get in the way

- **RLS in place.** Test each operation (SELECT/INSERT/UPDATE/DELETE) separately. Find the gap.
- **Auth required.** Sign up. Many apps don't restrict signup.
- **Email verification.** Use a real email or mailcatch service. Some apps skip verification under specific conditions.
- **Server-side validation.** If the app routes through its own backend before hitting Supabase, you're testing the backend, not Supabase directly.

## Escalation paths

1. **PII dump via PostgREST.** `users` or `profiles` table with no RLS = all PII.
2. **Cross-tenant data access.** Multi-tenant apps where `tenant_id` isn't enforced.
3. **Service-role key compromise.** Total DB control + ability to deploy functions + change auth users.
4. **Auth provider mass-takeover via JWT secret leak.** Mint tokens for any user.
5. **Storage as malware/phishing host.** Public-write storage on a custom-domain CDN.

## What a real finding looks like

- The Supabase project ref + the anon key being used (the apikey is meant to be public, so safe to include in the report)
- The REST API request showing the unauth/cross-user access
- The decoded JWT proving the role you're operating under
- The table/storage path affected
- The fix: enable RLS on every table, write policies that check `auth.uid() = user_id` for both USING and WITH CHECK, use service-role key only in Edge Functions and never in client code, audit functions for explicit auth checks

## Common false positives

- **Anon key visible in JS — looks like a leak, isn't.** The anon key is public by design. Only flag if it grants access to data it shouldn't.
- **`schema_migrations` table exposed.** Default PostgREST exposes it. Not sensitive but worth a hardening note.
- **Realtime WS connection fails after subscribe.** If you can't subscribe to a channel, that's working as designed (RLS applied).
- **403 on storage path.** Bucket is private. Not a finding.

## Related skills

`sql_injection` for direct SQL injection into PostgREST `rpc/` calls (custom Postgres functions), `idor` for the cross-user-data patterns, `information_disclosure` for the leaked-service-role-key channel.

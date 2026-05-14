---
slug: graphql
applies_to: [pentester, coder]
related: [idor, mass_assignment, business_logic, information_disclosure]
---

# GraphQL — Pentester Playbook

> Load this when recon found a GraphQL endpoint — typically `/graphql`,
> `/api/graphql`, `/query`, `/v1/graphql`. GraphiQL or Apollo Sandbox UIs
> at the same path are dead giveaways. Apollo Client / Relay / urql
> bundled in the JS also signals GraphQL.

## When to load this

Recon signals:

- A POST endpoint that accepts `{"query": "..."}` and returns `{"data": {...}}`
- GraphiQL / Apollo Sandbox at the endpoint URL (GET request returns the in-browser explorer)
- Apollo Federation gateway signals (`__service { sdl }` query works)
- Hasura signals (`/v1/graphql`, `/v1alpha1/graphql`)
- Relay signals (queries with `__typename`, fragment spreads, persisted query IDs)
- Common headers: `Apollographql-Client-Name`, `X-Apollo-Operation-Name`

The architectural realities you exploit:
- One endpoint, many "actions" — auth checks have to live in every resolver, not at the route level
- The schema is the API documentation — usually queryable
- Multiple queries can be batched or combined in one request — multiplies impact
- Resolvers cascade — a single query can hit dozens of DB tables; one weak resolver in the chain compromises the whole tree

## What you're looking for

Five common bug shapes:

- **Introspection enabled in production.** Anyone can query the full schema.
- **Field-level authorization gap.** A protected type has unprotected fields, or a protected type is reachable through an unprotected query.
- **IDOR via resolver.** Resolver takes an ID and returns the object without checking ownership.
- **Batching abuse.** No depth/complexity limits — attacker submits a deeply nested query that explodes into millions of DB queries.
- **Mutation that mass-assigns.** Mutation accepts an input type with too many fields, including server-managed ones.

## First moves

1. **Introspection probe.** Send a standard introspection query:
   ```json
   POST /graphql
   {"query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name}}}}"}
   ```
   If it returns the schema, introspection is on. Pull the full schema with a tool like `clairvoyance` or `graphql-cop`. The full schema is now your map.

2. **Even with introspection off — field guessing.** Common patterns:
   - `me`, `currentUser`, `viewer` — current user
   - `user(id: ID!)`, `users`, `accounts` — user lookups
   - `node(id: ID!)` — Relay's global node resolver (often unprotected)
   - `__type(name: "String")` — type introspection (sometimes still works even when full introspection is disabled)

3. **Error-leak fuzzing.** Send malformed queries (`{xx`, missing braces, unknown fields). The error message often leaks the schema piecemeal: "Cannot query field 'foo' on type 'User'. Did you mean 'email'?" — that response tells you `User` has an `email` field.

4. **Query depth bomb.** Send a query nested 50+ levels deep:
   ```graphql
   { user(id: 1) { friends { friends { friends { friends { ... } } } } } }
   ```
   If accepted (no depth limit error), you have a DoS primitive.

5. **Field duplication bomb.** Repeat the same expensive field many times in one query:
   ```graphql
   { a:expensiveOp b:expensiveOp c:expensiveOp ... z:expensiveOp }
   ```
   Same DoS shape, different vector. Aliases let you do this even when the field is "called once per query" by intent.

6. **Mutation enumeration.** From the schema, list every mutation. For each, send it with junk arguments. If it returns 200 + a "success" response, it ran. If it returns auth errors, it's gated — but the error message often tells you what's required.

## Confirming a hit

- **IDOR via resolver.** Query for another user's data by ID. The response should contain that user's private fields.
- **Mass assignment via mutation.** Submit a mutation with extra fields in the input. Re-query the affected object; the extra fields should be set.
- **Authorization gap.** Reach a protected type via an unprotected query path. Show the path in your finding.
- **DoS confirmation.** Show the response time / error / 504 from a depth or complexity attack. Don't actually take down production — measure with bounded queries.

## Going deeper — by GraphQL surface

### Introspection
- `{__schema}` — full schema dump (queries, mutations, types, all)
- `{__type(name:"X")}` — single type
- `__typename` is always queryable (even when introspection is "disabled" — it's part of the spec)
- Apollo Federation: `{ _service { sdl } }` returns the SDL even with introspection off

### Aliases
GraphQL lets you give any field an alias:
```graphql
{ a: user(id: 1) { name } b: user(id: 2) { name } c: user(id: 3) { name } }
```
This is one request, but the resolver runs three times. Uses:
- Bypass rate limiting (one HTTP request = many resolver invocations)
- Brute force login mutations (`{ a: login(p:"x") b: login(p:"y") ... }`)
- Enumerate IDs in a single request (`{ a:user(id:1) b:user(id:2) ... z:user(id:26) }`)

### Fragments
```graphql
fragment UserFields on User { id email role privateNotes }
{ users { ...UserFields } }
```
Used to factor out common selections. Bug shape: a fragment might select internal fields that the dev forgot were sensitive when used in a public query path.

### Subscriptions
WebSocket-based real-time updates. Often have weaker auth than queries/mutations because they were added later or use a different transport.

### Batched queries
Some servers accept arrays of operations:
```json
[{"query":"{a:user(id:1){...}}"},{"query":"{b:user(id:2){...}}"}]
```
Or batching via Apollo's HTTP batch link. Tests rate limits, auth uniformity across batched ops.

### Persisted queries
Apollo and Relay support persisted queries — client sends an ID hash instead of the full query, server looks up the registered query. Bugs:
- Server falls back to running the query if it's not in the registry (defeats the protection)
- Server registry is editable by clients (you can register your own queries with arbitrary content)

### `node(id:)` (Relay global node)
Relay convention: every object has a global ID, every server has a `node(id: ID!)` resolver that returns any object by ID. The IDs are usually base64 of `Type:id` (e.g., `VXNlcjox` = "User:1"). Decode the IDs you see to map the global ID space, then probe `node(id: "...")` with other types' IDs.

### Federation (Apollo Federation, Hasura Remote Schemas)
Multiple GraphQL services stitched into one. Each service has its own auth. Cross-service queries (`@requires`, `@external`) often skip auth on intermediate hops. Test queries that traverse service boundaries.

### Hasura-specific
- `/v1/graphql` is the user-facing endpoint
- `/v1/metadata` is admin (sometimes exposed)
- `/v1/query` accepts raw SQL when admin role is provided
- Hasura console (often at `/console` or a port like 8080) — often left open
- `x-hasura-admin-secret` header — if accepted from clients, complete bypass

## When filters get in the way

- **Introspection disabled.** Use error-based enumeration (typo'd fields reveal valid fields), use `__typename` enumeration, use mutual-information probes (send fields one at a time and see which 200 vs which error).
- **Depth limit enforced.** Calculate the limit (the error message often quotes it). Run queries just below the limit.
- **Query complexity scoring.** Tougher to bypass. Often the scoring is naive — fields with arguments score higher than fields without; you can sometimes craft expensive queries that score low.
- **Allowlist of operations.** Persisted-queries-only mode. Look for registry tampering bugs or fallback bypasses.
- **Auth required for queries.** Sign up, then re-probe — authenticated GraphQL surfaces are bigger than anon ones.

## Escalation paths

1. **Schema leak → mutation enumeration → mass assignment / privilege escalation.**
2. **IDOR via `node(id:)` → cross-user data → cross-tenant pivot.**
3. **Alias-based brute force on login mutations → account takeover.**
4. **Depth/complexity DoS → app outage.**
5. **Hasura admin secret leak → full DB access.**

## What a real finding looks like

- The exact GraphQL operation (query/mutation) that triggers the bug
- The response showing the data or behavior
- The schema fragment relevant to the bug (the resolver and type involved)
- For batching/complexity bugs: the response time / error showing the impact
- The fix: disable introspection in prod, add field-level authorization directives or middleware, enforce depth and complexity limits, use input-type allowlists for mutations

## Common false positives

- **Schema endpoints return errors that look like introspection.** Some servers return "introspection disabled" for some queries but allow `__typename`. Confirm by trying the full `{__schema}` query.
- **Mutation 200 that didn't change anything.** Some servers return 200 + null data without erroring. Re-query the affected object to confirm the change took effect.
- **Federation type errors that look like security gaps.** Sometimes cross-service queries fail with `external field unauthorized` — that's the federation gateway enforcing, not a bug.
- **`node(id:)` returning null.** Could be the object doesn't exist OR the auth filter returned null. Try multiple IDs to differentiate.

## Related skills

`idor` for the resolver-level cross-user data access, `mass_assignment` for the mutation-input bug shape, `business_logic` for multi-mutation workflow attacks, `information_disclosure` for the schema-and-error-leak channel.

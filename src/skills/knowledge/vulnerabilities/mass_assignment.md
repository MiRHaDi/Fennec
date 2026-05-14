---
slug: mass-assignment
applies_to: [pentester]
owasp: A08
related: [idor, broken_function_level_authorization, business_logic]
---

# Mass Assignment — Pentester Playbook

> Load this when recon found APIs that accept JSON/form bodies and bind
> them to internal models — Rails ActiveRecord, Django REST Framework
> serializers, Spring `@RequestBody`, Express body-parser into ORM, etc.

## When to load this

Mass assignment is the bug where the API blindly merges request body fields into a server-side object. It's especially common in:

- Auto-generated REST scaffolds (Rails generators, Django CRUD viewsets, NestJS resource generators)
- "Update profile" / "edit account" endpoints that take a JSON blob
- Bulk import endpoints (CSV → records, JSON → records)
- API endpoints whose only OpenAPI spec is `body: object` (no schema)
- Admin panels that share request handlers with public endpoints
- GraphQL mutations that take input objects

The recon signals that elevate priority:

- An endpoint accepts arbitrary fields without 400-ing on unknown ones
- The response body shows model fields like `is_admin`, `created_at`, `tenant_id`, `verified` — meaning they exist on the model
- Source code (if available) shows `Model.update(params)` or `Model(**request.json)` patterns
- The framework is one of the known offenders (Rails before strong_parameters, Django without explicit `fields`)

## What you're looking for

Three exploit shapes from the same underlying bug:

- **Privilege flip.** Send `{"role": "admin"}` or `{"is_admin": true}` in a request that updates your own profile.
- **Cross-account binding.** Send `{"user_id": OTHER_USER_ID}` in a request that creates an object — the object gets created with you owning it… or with you ON the other user's record.
- **Internal-only field tampering.** Send `{"created_at": "2010-01-01"}`, `{"price": 0}`, `{"verified": true}`, `{"is_paid": true}` — any field the app trusted to be server-managed.

## First moves

1. **Enumerate the model surface.** Pick an endpoint that updates an object (e.g., `PATCH /api/users/me`). First, do a normal update with one allowed field (e.g., `{"name": "x"}`). Save the response — it usually echoes the full object, revealing every field name on the model.

2. **Field probe.** From the response, extract field names that look "interesting": `role`, `is_admin`, `is_superuser`, `tenant_id`, `account_id`, `verified`, `is_paid`, `plan`, `credits`, `discount_percent`, `created_at`, `email_verified`. Send a PATCH attempting to set each. Watch for:
   - 200 + response shows the change → mass assignment confirmed
   - 200 + response shows old value (silent ignore) → server filters but doesn't reject
   - 400 with "unknown field" → server is strict (good for them)
   - 500 → flag for investigation

3. **Field-name fuzzing.** Try common admin field names even if you didn't see them in the response:
   - `role`, `roles`, `permission`, `permissions`, `is_admin`, `isAdmin`, `is_superuser`, `is_staff`, `admin`
   - `tenant`, `tenant_id`, `account_id`, `customer_id`, `organization`, `org_id`
   - `verified`, `is_verified`, `email_verified`, `is_active`, `enabled`, `disabled`
   - `balance`, `credit`, `credits`, `points`, `discount`, `discount_percent`
   - `password`, `password_hash`, `secret`, `api_key`, `recovery_codes`

4. **Nested object probe.** Models often have nested associations. Send `{"profile": {"role": "admin"}}` or `{"settings": {"is_paid": true}}` — some frameworks deep-merge nested objects, sometimes onto the *parent* object's fields.

5. **HTTP verb probe.** Try the same body with PATCH, PUT, POST. Sometimes the mass-assignment vulnerability is only on the "create" path, not the "update" path (or vice versa).

6. **GraphQL specific.** For `mutation { updateUser(input: {...}) { ... } }`, try adding fields not in the input type's schema. Some GraphQL servers are lenient.

## Confirming a hit

The proof of mass assignment is the model's state changing in a way the public API "shouldn't" allow:

- **Read-back confirmation.** After PATCH with the tampered field, GET the same resource. The new value should be present.
- **Behavioral confirmation.** After setting `is_admin: true`, try accessing an admin endpoint. If it works (where it failed before), the role flip is real.
- **Independent verification.** If you're claiming you set someone else's field, have a second account verify the change from their side.

## Going deeper — by framework

### Ruby on Rails
- **`strong_parameters` missing or wrong.** `params.permit!` is permit-everything (the bug). `params.permit(:name)` is correct. `params.require(:user).permit!` is also bug-shaped.
- **Mass assignment via nested attributes.** `accepts_nested_attributes_for :profile` exposes `profile_attributes` for binding even if you don't permit `profile_attributes` explicitly.
- **Old Rails (< 4) with `attr_accessible` only.** Many models lack the safelist; whatever you send binds.

### Django / DRF
- **`Meta.fields = '__all__'`.** Default in scaffolded serializers. Every model field is writable via the API, including FKs.
- **`ModelSerializer` with no field whitelisting.** Effectively the same problem.
- **`update_or_create(defaults={**request.data})`.** Direct mass-assign anti-pattern.

### Spring (Java)
- **`@RequestBody` with full model class.** `@RequestBody User user` binds every property of `User` from the request. If `User` has `roles: List<Role>`, send roles in the body.
- **Spring Data REST.** Auto-exposes repositories as REST endpoints by default. Every entity field is settable.
- **Jackson `@JsonIgnore` missing.** Server developer thought "this won't be serialized in responses, so it's safe to skip." But Jackson deserializes input too — without `@JsonIgnore` on both directions, the field is settable.

### Node.js / Express
- **`Model.findByIdAndUpdate(id, req.body)`** in Mongoose — direct mass-assign.
- **Sequelize `update`** with `req.body` and no `fields:` filter.
- **`Object.assign(existing, req.body)`.** The functional-language version of mass assign.

### .NET
- **MVC model binding.** `[HttpPost] public IActionResult Update(UserModel u)` binds every field of `UserModel`. If `UserModel` has an `IsAdmin` property used internally, sending it from the client overrides.
- **EF Core `Entry(model).CurrentValues.SetValues(input)`.** Standard pattern that's vulnerable when `input` is `req.Body`.

## When filters get in the way

- **Allowlist of known fields.** Hard to bypass. But: check for typos or case sensitivity. If the allowlist is `["name", "email"]`, try `Name`, `EMAIL`, `email_`, `_email`.
- **Type-only filtering.** Some frameworks check the type of each field but not the field name itself. Sending `role` as a string when the model expects an int will be filtered, but as an int it might bind.
- **JSON property aliases.** Jackson supports `@JsonAlias`. If the field has aliases, try them.
- **GraphQL input types.** Schema-enforced. But: try sending unknown fields anyway, and try sending fields from sibling input types.
- **Request signing.** Some APIs HMAC the request body — tampering invalidates the signature. Look for a separate "internal" endpoint that doesn't sign.

## Escalation paths

1. **Self-promotion to admin.** The classic — set `role: admin` on your own user record.
2. **Cross-tenant pivot.** Set `tenant_id` to another tenant's ID. Subsequent reads/writes use the new tenant scope.
3. **Verification bypass.** Set `email_verified: true` without owning the email; unlocks features gated by verification (password reset, payouts).
4. **Free premium.** Set `is_paid: true`, `plan: enterprise`, `credits: 999999` on your own account.
5. **Audit trail tampering.** Set `created_at` to before the bug was introduced. Set `created_by` to a different user to misattribute actions.
6. **Cascading auth.** If the model has a `roles: [...]` field, set it to include admin-level roles. Some apps re-read the role list on every request.

## What a real finding looks like

- The exact PATCH/POST request with the tampered field highlighted
- The response showing the field accepted (or the follow-up GET if the response doesn't include the field)
- The behavioral consequence: a follow-up request demonstrating the new privilege/state ("with `is_admin: true` set, the admin endpoint `/api/admin/users` returned 200 + user list, previously returned 403")
- The framework + the specific anti-pattern detected ("Django DRF serializer with `Meta.fields = '__all__'`")
- The fix: serializer/DTO with explicit allowlist of input fields, separate from the model. Internal-only fields should be on the model but not on the DTO.

## Common false positives

- **Field appears in response but isn't set.** Some serializers echo any field present in the request, then ignore it during persistence. Confirm with a follow-up GET from a fresh request — if the field returns to the original value, it wasn't actually set.
- **Read-only fields that error silently.** Server logs a warning, drops the field, returns 200. Looks like success, isn't. Same confirmation: re-fetch and compare.
- **GraphQL extra fields ignored.** GraphQL servers usually return a clear error for unknown input fields. If they don't error, sometimes they just drop. Always re-fetch to confirm state.
- **Setting a field whose value was already what you sent.** Trivial coincidence. Confirm by setting to a different value than the current one.

## Related skills

`idor` for the cross-account targeting that pairs with mass assignment, `broken_function_level_authorization` for the role-bypass after privesc, `business_logic` for the workflow-state tampering shapes.

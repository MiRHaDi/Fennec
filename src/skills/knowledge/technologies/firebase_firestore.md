---
slug: firebase-firestore
applies_to: [pentester, coder]
related: [idor, broken_function_level_authorization, information_disclosure]
---

# Firebase / Firestore — Pentester Playbook

> Load this when recon found a Firebase or Firestore footprint — calls to
> `*.firebaseio.com`, `*.firebaseapp.com`, `firestore.googleapis.com`,
> Firebase SDK in JS bundles, or Firebase config blobs in HTML/JS.

## When to load this

Recon signals that trigger this:

- Network requests to `*.googleapis.com/v1/projects/*/databases` (Firestore REST)
- `firebase.initializeApp({apiKey: "...", projectId: "...", ...})` in JS
- `<script src="https://www.gstatic.com/firebasejs/...">` in HTML
- Realtime Database URLs (`https://<project>.firebaseio.com/...`)
- Auth endpoints under `*.identitytoolkit.googleapis.com`
- App-side use of `firebase/firestore`, `firebase/auth`, `firebase/storage` packages

The architectural reality: Firebase apps put massive trust in the client. The client SDK talks directly to Firestore/Auth/Storage. The only thing standing between an attacker and the data is the security rules. If rules are weak, the app is weak — full stop.

## What you're looking for

Five common bug shapes:

- **Open Firestore.** Rules allow read/write to all authenticated users (or worse, all visitors). `match /databases/{database}/documents { allow read, write: if true; }` is the textbook misconfig.
- **Auth-bypass rules.** Rules check `request.auth != null` but not which user — any authenticated user can read/write any document.
- **Ownership-rule gaps.** Rules check `request.auth.uid == resource.data.userId` for read, but not for write — anyone can write into anyone's document.
- **Cloud Function auth gaps.** Callable Cloud Functions or HTTPS Cloud Functions that don't verify the caller's identity.
- **Service Account leak.** Service account JSON committed to the repo or exposed via misconfigured Storage. Service accounts bypass all security rules.

## First moves

1. **Extract config.** Pull the Firebase config blob from the app's JS:
   ```js
   const firebaseConfig = {
     apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
     authDomain: "myapp.firebaseapp.com",
     projectId: "myapp",
     storageBucket: "myapp.appspot.com",
     ...
   };
   ```
   `apiKey` is NOT a secret — it's a public client identifier. `projectId` is what you need.

2. **Direct Firestore probe.** With just the `projectId`, try reading the database without auth:
   ```
   GET https://firestore.googleapis.com/v1/projects/<projectId>/databases/(default)/documents/<collection>
   ```
   If you get a 200 with data, the collection is publicly readable (rules allow `read: if true` or similar).

3. **Common collection names.** If you don't know collection names, try the obvious: `users`, `accounts`, `orders`, `messages`, `posts`, `profiles`, `settings`, `config`, `secrets`. Firebase doesn't enumerate collections via API — you have to know or guess names.

4. **Unauth write probe.** With a single document path, try to write:
   ```
   POST https://firestore.googleapis.com/v1/projects/<projectId>/databases/(default)/documents/<collection>
   Content-Type: application/json
   {"fields": {"x": {"stringValue": "test"}}}
   ```
   If 200, anonymous write is open. This is a critical finding.

5. **Realtime Database probe.** If `databaseURL` is in config:
   ```
   GET https://<project>.firebaseio.com/.json
   ```
   `?shallow=true` returns top-level keys without values — quick enumeration without dumping the whole DB. If this returns data, the entire DB is publicly readable.

6. **Storage bucket probe.** From config's `storageBucket`:
   ```
   GET https://firebasestorage.googleapis.com/v0/b/<bucket>/o?prefix=
   GET https://storage.googleapis.com/<bucket>/
   ```
   If listed, every uploaded file is enumerable.

7. **Authenticate as anonymous.** Sign up for anonymous auth via the Identity Toolkit API:
   ```
   POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>
   {"returnSecureToken": true}
   ```
   Returns an `idToken`. Now you're authenticated. Re-probe everything that required auth — many apps have `request.auth != null` rules that any authenticated user (including you) satisfies.

8. **Privilege probe with anonymous token.** With your fresh anonymous ID, try to read/write other users' data. Anonymous users authenticating with a real token can pass `request.auth != null` checks and trigger IDOR-style access.

## Confirming a hit

- **Unauth read.** The Firestore REST endpoint returned actual data without an `Authorization` header.
- **Authed write to non-owned resource.** You wrote a document into another user's collection while authenticated as your own (or anonymous) account, then verified the write took effect.
- **Storage listing.** Listed bucket contents and downloaded a non-public file.
- **Cloud Function unauthed.** Called a callable function and got a successful response without providing auth context.

## Going deeper — by surface

### Firestore Security Rules
The rules language is its own thing. Common patterns and their weaknesses:

```js
// BAD — anyone can read everything
match /{document=**} {
  allow read: if true;
}

// BAD — any authenticated user can read/write all
match /{document=**} {
  allow read, write: if request.auth != null;
}

// PARTIALLY BAD — owner-check on read, no check on write
match /users/{userId} {
  allow read: if request.auth.uid == userId;
  allow write: if request.auth != null;  // <-- bug
}

// SUBTLY BAD — uses resource.data which is the OLD data on writes
match /users/{userId} {
  allow read: if request.auth.uid == resource.data.ownerId;
  // OK for read, but on create/update should use request.resource.data
}
```

Test each collection's rules empirically:
- Read your own doc (should work)
- Read someone else's doc (should fail)
- Write to your own doc (should work)
- Write to someone else's doc (should fail)
- Delete your own doc (varies by app)
- Create a new doc with `ownerId` set to your UID (should work)
- Create a new doc with `ownerId` set to another UID (should fail; if it succeeds, you can plant docs on victims' accounts)

### Cloud Functions
Two flavors:
- **HTTPS Cloud Functions.** `https://us-central1-<project>.cloudfunctions.net/<funcName>`. These are open HTTP endpoints; auth is the dev's responsibility.
- **Callable Cloud Functions.** Called via the SDK; receive `context.auth` populated by Firebase. If the function doesn't check `context.auth`, anyone can call.

Common bugs:
- HTTPS function that uses Admin SDK without verifying caller
- Callable function that trusts a userId in its arguments instead of using `context.auth.uid`
- Function that performs admin-only logic but has no role check

Enumerate functions via JS bundles — `httpsCallable(functions, "deleteUser")` reveals the function name.

### Storage Rules
Same rules language as Firestore but for files. Common bugs:
- `allow read: if true;` — public bucket masquerading as private
- `allow write: if request.auth != null;` — any user can upload anywhere (XSS via HTML upload, malware staging)
- Filename collision: any user can overwrite anyone's profile picture by uploading to the same path

### Firebase Auth
- **Anonymous signup enabled.** Common; lets you bootstrap an authenticated identity for free.
- **Custom claims trust.** If the app sets custom claims via Admin SDK based on a request value, and the request value is client-controlled, you can self-grant admin via the auth API.
- **MFA bypass.** Firebase Auth MFA is opt-in; many apps don't enforce.
- **Phone auth abuse.** SMS-based recovery flows are racy; check for phone number rebinding via parallel update requests.

### Firebase Realtime Database
The older DB product. URL pattern `https://<project>.firebaseio.com/path.json`. Rules look like:
```json
{ "rules": { ".read": "auth != null", ".write": "auth != null" } }
```
Wildcards (`$uid`) work but ownership checks are easy to miss. Same probe pattern as Firestore.

### Service Account leak
Service Account JSON files have private keys. Anywhere they're committed = anywhere they bypass all rules. Search for:
- `serviceAccountKey.json` in git history
- Files starting with `-----BEGIN PRIVATE KEY-----` in JS bundles
- Cloud Storage buckets containing `service-account*.json` files

If you find one, the project is fully compromised — you can read/write everything in Firestore, deploy functions, change Auth users, anything.

## When filters get in the way

- **Rules check `request.auth.token.email_verified`.** Bypass by completing email verification on your test account (anonymous accounts can't, but normal signups can).
- **App Check.** Firebase App Check ties requests to verified app instances (via Play Integrity, App Attest, reCAPTCHA). If enforced, direct REST API calls fail. Bypass: the App Check token is sometimes generatable via debug tokens that leak in dev builds.
- **Custom token validation.** Some apps validate `idToken` server-side via their own middleware before allowing Firestore access. In those cases, you're not talking to Firestore directly anyway — the bug is in the middleware.

## Escalation paths

1. **PII enumeration.** `users` collection readable → email + phone + address of every user.
2. **Cross-tenant writes.** Write into another user's `documents` → modify their data, plant content.
3. **Privilege flip via custom claims.** Mass-assign-style write to a `roles` collection that Cloud Functions read.
4. **Storage XSS / shell upload.** Public-write storage with HTML uploads served from the app's origin = stored XSS or RCE if the storage is served as code.
5. **Service Account compromise.** Full project takeover.

## What a real finding looks like

- The exact REST API endpoint hit + the response body proving the unauth/cross-user access
- The relevant rule snippet (if you can infer from behavior; or note that rules can't be read from outside)
- The data class exposed (user records, payment info, internal docs) with one redacted sample
- The fix: rules audit, specifically test that rules deny by default, App Check enforcement, service-account hygiene

## Common false positives

- **API key looks leaked but isn't sensitive.** Firebase apiKey is public by design. Calling it "exposed" is wrong. The real check is whether the rules let unauth use the key for anything sensitive.
- **403 on direct REST that's reachable via the SDK.** Sometimes the SDK adds tokens you don't have. Try mimicking the SDK's headers (`Authorization`, `X-Firebase-AppCheck`, etc.).
- **Rules show as restrictive in the simulator but permissive in practice.** Simulator doesn't always match deployed behavior. Always test with real REST calls.
- **Cloud Function 401.** Function checks `context.auth`. Not a bug.

## Related skills

`idor` for the cross-user-data-read patterns, `broken_function_level_authorization` for the Cloud Functions admin-only logic, `information_disclosure` for the leaked-service-account-key channel.

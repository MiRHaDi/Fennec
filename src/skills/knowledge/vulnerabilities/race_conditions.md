---
slug: race-conditions
applies_to: [pentester]
owasp: A04
related: [business_logic, idor, authentication_jwt]
---

# Race Conditions — Pentester Playbook

> Load this when recon found endpoints that perform a check-then-act
> pattern: balance check + debit, coupon validity + apply, "is this code
> already used?" + use, "are you the resource owner?" + delete. Race
> conditions live in the gap between the check and the action.

## When to load this

The endpoint shapes that almost always have race conditions:

- Money movement: transfer, refund, payout, withdrawal, gift-card redemption
- Single-use codes: coupons, invitations, password reset tokens, MFA backup codes
- Limited inventory: ticket sales, "first 100 free", seat allocation
- Rate-limited actions: "you can do this once per hour"
- Account creation: "this email is unique" check
- Resource creation with a uniqueness constraint enforced in app code (not DB)
- Subscription / billing state transitions

The recon signals:

- Synchronous APIs (the server holds the request open until done — easier to race than async queue-based)
- Read-then-write patterns in source code (`if user.balance >= amount: user.balance -= amount`)
- No explicit DB transaction or row-level lock in the handler

## What you're looking for

Race conditions have four shapes:

- **Time-of-check / time-of-use (TOCTOU).** Check happens at T=0, action at T=1, attacker changes state between them.
- **Limit overrun.** Limit check (`if user.coupon_uses < 1`) passes for two parallel requests because each sees the pre-decrement value.
- **Idempotency violation.** "Mark this as used" runs twice because the "is it used?" check sees `false` in both threads before either writes `true`.
- **State-machine fork.** Two parallel transitions of the same resource leave it in two contradictory states (or one of the states "wins" silently).

## First moves

1. **Identify the candidate.** From recon, pick an endpoint that:
   - Performs a check (limit, balance, uniqueness, ownership)
   - Then performs an action that depends on the check
   - The state change isn't obviously transactional

2. **Build the request manually.** Capture a normal request that succeeds (you redeem one coupon, you transfer $10). Save the full request — every header, the exact body.

3. **Send N copies in parallel.** Use the right tool for the job:
   - **Burp Repeater "Send Group in Parallel"** with single-packet attack mode — the canonical SSL race tool, opens N HTTP/2 streams and sends the final byte of each in a single TCP packet
   - **`turbo-intruder`** (Burp extension) with `race-single-packet-attack.py` script
   - **`oxnr`** / custom python: `asyncio.gather([client.post(...) for _ in range(20)])`
   - **`h2c-smuggler`** for HTTP/2-specific races where the upstream parser is HTTP/1.1
   
   Start with N=20. If nothing happens, push to N=100. If even that doesn't, the endpoint may not be raceable (DB constraint or single-threaded handler).

4. **Read the outcomes.** Count successes vs failures vs errors. Possible outcomes:
   - 1 success, 19 "already used" → check is enforced, race didn't win
   - 2-5 successes, rest "already used" → race window exists, partial enforcement (you got 2-5× the intended limit)
   - All 20 successes → no enforcement (effectively no limit)
   - Mixed 200/500 → race triggered an error path; investigate the side effects

5. **Confirm with state inspection.** After the parallel burst, check the state directly: how many coupon uses are recorded? How much money moved? If 5 coupons were "redeemed" but only one shows in your account, the race took effect on a hidden counter.

## Confirming a hit

Race condition findings need clean repros:

- **Parallel-shot evidence.** The burst of N requests + the count of successes that exceeds the intended limit. Screenshot of Burp's response table is canonical.
- **Side-effect state.** Show the affected resource (balance, counter, redemption log) before and after — the delta should exceed what should have been possible.
- **Reproducible.** Run the burst from a fresh test account. If it reproduces, it's not a one-time flake.

## Going deeper — by target

### Single-packet attack (the technical core)
The classic challenge with HTTP races over the internet: latency variance between requests. The single-packet attack solves this:

1. Open N HTTP/2 streams to the target (HTTP/2 multiplexes streams over a single TCP connection)
2. Send each stream's request fully EXCEPT the last 1-2 bytes
3. In a single `send()` call to the OS, send the final byte for each stream
4. All N requests arrive at the target's HTTP parser in the same TCP packet, processed back-to-back-to-back with sub-ms gaps

Without HTTP/2 (target is HTTP/1.1 only): use connection warming + nagle disable, or chain via h2c-smuggler if the front-end allows.

### Limit-bypass races
- **Coupons / promo codes.** Race 10× redemption of a 1-use code. Outcomes: 1 success (good), 10 successes (vulnerable, multi-use achieved), 5 successes (partial — the DB or cache caught some).
- **Free trials / signup credits.** Race signup with the same email. If 2+ succeed, you have 2× the signup bonus on parallel accounts.
- **API quotas.** Race 100 requests in 100ms. If all 100 succeed when the quota is "10 per second", the quota check has a race.

### Money-movement races
- **Withdrawal / transfer.** Send 10 parallel "withdraw $100" requests with balance=$100. If 2 succeed, you withdrew $200 from a $100 balance (negative balance or hidden debt created).
- **Refund double-credit.** Submit 10 parallel "refund order X" requests. If multiple succeed, the order is refunded multiple times.
- **Gift card redemption.** Race redemption of a 1-use gift card from two accounts.

### Auth / token races
- **Password reset.** Submit 10 parallel "set new password to X" requests using the same one-time reset token. If multiple succeed, the token isn't consumed.
- **MFA backup code.** Use the same backup code from 10 parallel requests; if multiple succeed, the code isn't atomically consumed.
- **OAuth code exchange.** Submit the same auth code 10× in parallel; if you get 10 valid access tokens, the code isn't single-use.

### State-machine races
- **Order state.** Submit "cancel order" and "ship order" in parallel. Both might succeed, leaving an order in two contradictory states.
- **Account upgrade/downgrade.** Race "upgrade to pro" and "downgrade to free" — both succeed, account state becomes inconsistent.
- **Approval workflow.** Race "approve" and "deny" — both run, the last-write-wins might be the wrong one.

## When filters get in the way

- **DB unique constraint.** The DB itself rejects duplicates. Most race conditions on uniqueness are caught here. But: the constraint might only be at app level, not DB, or only on a subset of fields.
- **Idempotency key required.** Server rejects duplicate idempotency keys. But: the check might happen AFTER the action, or the keys might be cached separately from the action's state.
- **Row-level locking.** `SELECT ... FOR UPDATE` blocks concurrent reads. If you see this in source, races on that row are eliminated. Check siblings — `users.balance` might be locked but `users.credits` might not be.
- **Single-process handlers.** If the app is single-threaded (Python GIL-bound + synchronous), races are limited to whatever happens at the I/O boundary (DB reads/writes). Still raceable, but the window is narrower.
- **Distributed locks (Redis SETNX, Zookeeper).** Better than nothing, but Redis-based locks have their own race conditions (key expiry mid-transaction, network partitions).

## Escalation paths

1. **Money out the door.** Free withdrawals, double refunds, balance going negative.
2. **Unlimited "limited" items.** Coupons redeemed N times, signup bonuses claimed N times, free trial restarted N times.
3. **Account takeover.** Password reset token reuse → set password on victim account.
4. **Permission escalation.** Race promote-to-admin during a window where the original admin demotes you back, end state is admin.
5. **Inconsistent state weaponization.** Order shipped without payment, subscription active without billing.

## What a real finding looks like

- Burp request file + the parallel-send configuration used (number of streams, timing)
- Response table from Burp showing the multiple-success outcome
- The state of the affected resource after (balance/count/redemption log) showing the impossible value
- The handler source (if available) showing the missing transaction/lock
- The fix specific to the race: use DB-level uniqueness constraint, use SELECT FOR UPDATE inside a transaction, use atomic counters (`UPDATE x SET counter = counter - 1 WHERE counter > 0`), use distributed locks with proper expiry/fencing

## Common false positives

- **Burp "parallel" without single-packet attack.** Sequential requests across a few ms — the second request sees the first's effects. Not a real race; you need true simultaneity.
- **Apparent races caused by retries.** If your client retried a request that the server already processed, you might see N successes when only one happened on the server. Read server logs to confirm.
- **Race wins that the system later reconciles.** Some apps allow temporary inconsistency and reconcile via a cron job. If your "exploit" disappears after a few minutes, the system caught it.
- **Idempotency working as designed.** If you send 10 requests with the same idempotency key and get 1 success + 9 "duplicate, returning cached response", that's correct behavior, not a vuln.

## Related skills

`business_logic` for the parent class (race conditions are a flavor of business logic), `idor` for the cross-user race targeting, `authentication_jwt` for the token-reuse race shapes.

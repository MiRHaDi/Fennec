---
slug: business-logic
applies_to: [pentester]
owasp: A04
related: [race_conditions, mass_assignment, idor]
---

# Business Logic Flaws — Pentester Playbook

> Load this when recon mapped multi-step workflows: checkout, refund,
> account upgrade, transfer, invitation, KYC, dispute, withdrawal. Business
> logic bugs live in the spaces between steps that no input-validation
> check covers.

## When to load this

Business logic is the catchall for "the app behaved according to spec but the spec is wrong." It's worth dedicated testing on anything that:

- Moves money (payments, refunds, transfers, payouts, withdrawals)
- Counts inventory or limits (seats, API quotas, free-tier limits)
- Has discrete state transitions (order: pending → paid → shipped → delivered)
- Includes negotiated values (price, discount, shipping, currency conversion)
- Enforces time windows (trial period, cancellation window, dispute window)
- Has a workflow approval chain (PR review, expense approval, KYC)
- Involves promotional logic (coupon codes, referral bonuses, points/credits)

The recon signals that elevate priority:

- Multiple endpoints involved in one user journey (signal: order has 3+ requests from add-to-cart to confirmation)
- Server-trusted client values (signal: the request body includes the price, not just the SKU)
- Stateful workflows with discoverable state machines
- Time-based logic (signal: `created_at`, `expires_at`, `valid_until` fields)

## What you're looking for

Business logic bugs don't have a payload template — they have a logic shape. The common families:

- **State skip.** Reach state N without going through state N-1. Pay-then-cancel without ever paying. Mark order shipped without it being paid.
- **State reverse.** Go backwards through a state machine. Un-cancel a cancelled order. Un-refund a refund.
- **Negative value.** Quantity = -1, amount = -100, transfer of negative money. If the system multiplies, negative × cost = credit.
- **Boundary value.** Off-by-one on free-tier limits, expiry comparisons (`<` vs `<=`), max-value overflow.
- **Race-based.** Submit the same action twice in parallel; one of the two slips through after the rate-limit check but before the "already used" check. (See `race_conditions` skill for the dedicated playbook.)
- **Workflow-context bypass.** Action requires precondition X, but X can be set/forged on a sibling endpoint without authorization.
- **Currency/unit confusion.** Backend expects USD cents, frontend sends USD dollars → 100× discount. Or amount field changes units between steps.
- **Trust delegation.** "I'm an authorized internal caller" header injection; "this transaction is internal" body flag.

## First moves

The general method: **map the workflow, then test every transition**.

1. **Walk the happy path end-to-end** while capturing every request. For a 5-step checkout, you'll have 8-12 HTTP requests. Annotate each with what state it advances to.

2. **Identify trust boundaries.** For each request, which fields does the server believe vs derive? If `price` is in the request body, the server probably trusts it. If `order_total` only appears in the server's response, the server derived it. Trusted-from-client fields are your hypothesis pile.

3. **For each step, test:**
   - **Skip it entirely.** Call step N+1 directly without doing step N.
   - **Repeat it.** Submit step N twice with the same nonce/order_id.
   - **Negate any numeric.** Replace `quantity: 5` with `quantity: -5`. Submit. Same for `amount`, `discount_percent`, `days`.
   - **Substitute IDs from a different account.** Apply your coupon to victim's order. Submit a refund on someone else's purchase. (Pairs with `idor`.)
   - **Tamper time.** If a field controls validity (`expires_at`), set it to the past or far future.

4. **Test the unhappy paths.** What happens if you submit step 3 of a 5-step flow with the state from step 1? What if you cancel and then try to confirm? What if you confirm and then try to cancel after shipping?

5. **Boundary scan.** Free tier limit = 10 projects? Create 9, 10, 11 in rapid succession. Trial expires after 14 days? Move your account clock (cancel trial day 14, immediately re-subscribe — does the new trial reset to 14 days?).

## Confirming a hit

Business logic confirmations are reproductions, not payloads. The proof:

- **End state shows the impossible outcome.** Order in "shipped" state with `paid_amount: 0`. User in "premium" tier with no `subscription_id`. Coupon code with `times_used: 1` but applied to 5 orders.
- **Money moves in the wrong direction.** Refund balance shows your account credited for a purchase you never made (negative amount in a transfer field).
- **State transition log shows the gap.** Read the audit log / activity timeline — if it shows "Order created → Order shipped" with no payment event, the skip is logged.
- **Repro from a fresh account.** Always re-run the exploit from a fresh test account before reporting. If it works twice from scratch, it's not flaky.

## Going deeper — by workflow type

### E-commerce checkout
- **Coupon stacking.** Apply two single-use codes that "shouldn't" stack. Apply the same code on two parallel sessions.
- **Cart manipulation.** Reduce quantity to 0 (some systems compute total before validating qty). Negative quantity. Item added then removed but discount calculated from removed item.
- **Currency.** Pay in JPY (where 100 JPY ≈ $1) for a USD-priced item; some systems convert at checkout but display in the original. Trick: pay for a USD product in a currency where the same number is much cheaper.
- **Shipping/tax.** Submit billing/shipping addresses that pass validation but trigger zero-tax calculation; pickup-in-store flag that zeroes shipping then changes mind.

### Banking / transfers
- **Negative transfer.** "Transfer -$100 from victim to attacker" = $100 transferred FROM victim TO attacker if the sign isn't validated.
- **Self-transfer.** Some systems double-credit on self-transfer because the "credit destination" code runs before "debit source" fails.
- **Beneficiary swap mid-flow.** Initiate transfer to legitimate beneficiary, change beneficiary ID just before confirmation step.

### Account upgrade / downgrade
- **Downgrade-then-upgrade refund.** Downgrade from premium to free (gets prorated refund), upgrade back to premium (pay nothing because plan switch within billing cycle).
- **Trial re-roll.** Cancel trial → delete account → create new account with the same email/payment → new trial.
- **Cross-plan feature carry.** Subscribe to premium, configure premium-only feature, downgrade → does the feature stop working, or does the existing config persist?

### KYC / verification
- **Auto-approve race.** Submit verification documents while editing identity info — race the verifier against your edit.
- **Document reuse.** Use the same KYC document for multiple accounts.
- **Verification bypass via support flow.** "Contact support" override endpoints sometimes skip the normal check.

### API quota / rate limits
- **Quota check after work.** API counts your request after it processes it. If you can crash mid-request, the count doesn't increment.
- **Cross-key quota.** API keys allegedly siloed, but quota counter is shared globally.
- **Quota reset trigger.** Cancel subscription → resub → counter resets even though it shouldn't.

## When filters get in the way

- **Required signature on amounts.** Some APIs HMAC the amount; tampering requires breaking the HMAC. Look at older endpoint versions, debug endpoints, "internal" endpoints that skip the signature.
- **Idempotency keys.** Server rejects repeated submission of the same key. But: what if you send the same business operation with different keys? Many systems only dedup on the key, not the operation.
- **State machine validation.** Server tracks state per-resource and rejects invalid transitions. But: what if you fork the state into a sibling resource (clone the order) and apply the transition there?
- **Audit logs.** Apps log every transition. Don't try to delete the log entries — they're not the bug. Use them as oracle for what the system thinks happened.

## Escalation paths

1. **Money out the door.** Refund manipulation, negative transfer, double-credit. Most business logic findings escalate here.
2. **Free premium.** Permanent free access to paid tier via state-skip on the "is_paid" boolean.
3. **Cross-customer impact.** Coupon you create eats from another customer's budget. Refund you process debits the wrong account.
4. **Loyalty/points farming.** Earn points without performing the underlying action (place order → cancel → keep points).
5. **Quota / limit bypass.** Free-tier user uses paid-tier features in unlimited quantities.

## What a real finding looks like

- Numbered reproduction steps starting from "create a fresh account with $X in test balance"
- The exact request/response pair for the manipulated step
- A screenshot of the impossible end state (order detail page showing shipped without paid, etc.)
- A second reproduction from a different fresh account, to prove non-flakiness
- The dollar-equivalent impact if exploited at scale ("each exploited refund nets the attacker $50; the endpoint has no rate limit; estimated maximum loss in 24 hours = $X")
- The fix: usually "validate the value/sign/precondition server-side" or "make this operation idempotent on the business key, not the request ID"

## Common false positives

- **Bugs that look like business logic but are just normal feature behavior.** "I cancelled and got a full refund" — yes, that's the policy. Find the bug version: "I cancelled day 31 of 30-day refund window and still got a full refund."
- **State changes that auto-correct.** Some systems "fix" weird states on a nightly cron. If your impossible state is resolved an hour later, you found something the system catches, not something it misses.
- **Sandbox-only behavior.** Staging environments often have payment-bypass flags that don't exist in production. Confirm against production scope (with permission and care) before reporting "negative transfers work."
- **Race conditions misclassified.** If the bug only fires under exact parallel submission, it's a race condition — use the `race_conditions` skill instead.

## Related skills

`race_conditions` for the parallel-submission variants, `mass_assignment` for the body-override class, `idor` for cross-account business logic.

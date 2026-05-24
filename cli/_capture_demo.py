#!/usr/bin/env python
"""
Renders a realistic-looking, mid-scan dashboard snapshot and saves it as
both SVG and PNG into docs/screenshots/. Used to generate the hero CLI
screenshot embedded in the README.

This is a one-shot capture script — not part of the user-facing CLI.
"""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from cli.interactive import DashboardState, DashboardRenderer, make_event_sink


def build_scene() -> DashboardState:
    """Hand-craft a dashboard state that looks like a scan caught mid-flight:
    recon done, analyst produced hypotheses, pentester running sqlmap, one
    finding confirmed."""
    state = DashboardState(
        target="http://fenneclabs.ai",
        method="balanced",
    )
    # Push the clock back so elapsed shows 02:38
    state.started_at = time.time() - 158

    state.current_agent = "pentester"
    state.current_node = "pentester"
    state.current_hypothesis_id = "h2"

    state.recon_paths = 47
    state.recon_services = 6

    # Hypothesis tree — mix of statuses to show the renderer's full palette
    state.hypothesis_tree = {
        "h1": {
            "id": "h1", "parent_id": None,
            "title": "SQL injection in /api/products?id=",
            "status": "completed", "result": "vulnerable",
            "severity": "critical", "priority": 0.95,
        },
        "h2": {
            "id": "h2", "parent_id": None,
            "title": "Authentication bypass on /admin",
            "status": "in_progress", "priority": 0.88,
        },
        "h3": {
            "id": "h3", "parent_id": "h1",
            "title": "Privilege escalation via SQLi in users table",
            "status": "pending", "priority": 0.82,
        },
        "h4": {
            "id": "h4", "parent_id": None,
            "title": "Stored XSS in /comments",
            "status": "pending", "priority": 0.65,
        },
        "h5": {
            "id": "h5", "parent_id": None,
            "title": "SSRF via image proxy endpoint",
            "status": "completed", "result": "safe",
            "priority": 0.55,
        },
        "h6": {
            "id": "h6", "parent_id": None,
            "title": "IDOR on /orders/{id}",
            "status": "pending", "priority": 0.50,
        },
    }
    state.pending_queue = ["h3", "h4", "h6"]

    # Findings — one critical (SQLi confirmed) + an info-level header finding
    state.findings = [
        {"title": "Union-based SQL injection in products endpoint",
         "severity": "critical",
         "description": "Concatenated query allows DB exfiltration"},
        {"title": "Missing Content-Security-Policy header",
         "severity": "low"},
        {"title": "Server banner discloses nginx version",
         "severity": "info"},
    ]

    # Activity log — recreate a believable last-14-events timeline
    state.activity.extend([
        {"ts": "14:02:11", "agent": "orchestrator", "kind": "node_update",
         "msg": "→ entered orchestrator"},
        {"ts": "14:02:14", "agent": "recon", "kind": "node_update",
         "msg": "→ entered recon"},
        {"ts": "14:02:18", "agent": "recon", "kind": "tool_call",
         "msg": "⮞ terminal(nmap -sV -p 80,443,8080 fenneclabs.ai)"},
        {"ts": "14:02:42", "agent": "recon", "kind": "tool_result",
         "msg": "← terminal: 80/tcp open  http  nginx 1.25.3"},
        {"ts": "14:02:51", "agent": "recon", "kind": "tool_call",
         "msg": "⮞ terminal(gobuster dir -u http://fenneclabs.ai -w common.txt)"},
        {"ts": "14:03:24", "agent": "recon", "kind": "agent_message",
         "msg": "recon snapshot: 47 paths · 6 services"},
        {"ts": "14:03:31", "agent": "analyst", "kind": "node_update",
         "msg": "→ entered analyst"},
        {"ts": "14:03:48", "agent": "analyst", "kind": "hypothesis",
         "msg": "hypothesis tree updated — 6 hypotheses in flight"},
        {"ts": "14:03:55", "agent": "pentester", "kind": "node_update",
         "msg": "→ entered pentester"},
        {"ts": "14:04:02", "agent": "pentester", "kind": "tool_call",
         "msg": "⮞ terminal(sqlmap -u 'http://fenneclabs.ai/api/products?id=1' --batch --dbs)"},
        {"ts": "14:04:18", "agent": "pentester", "kind": "tool_result",
         "msg": "← terminal: parameter 'id' appears to be 'MySQL >= 5.0 UNION query' injectable"},
        {"ts": "14:04:31", "agent": "pentester", "kind": "finding",
         "msg": "⚑ new finding — [CRITICAL] Union-based SQL injection in products endpoint"},
        {"ts": "14:04:38", "agent": "pentester", "kind": "tool_call",
         "msg": "⮞ terminal(curl -s -X POST http://fenneclabs.ai/admin/login -d 'u=admin&p=admin')"},
        {"ts": "14:04:44", "agent": "pentester", "kind": "tool_result",
         "msg": "← terminal: HTTP/1.1 401 Unauthorized"},
    ])

    # Latest tool call + result (drives the right panel)
    state.last_tool_call = {
        "tool_name": "terminal",
        "tool_id": "call_4",
        "agent": "pentester",
        "args": {
            "command": "sqlmap -u 'http://fenneclabs.ai/api/products?id=1' --batch --dbs --threads=4",
        },
    }
    state.last_tool_result = {
        "tool_name": "terminal",
        "tool_id": "call_4",
        "agent": "pentester",
        "success": True,
        "result": (
            "[14:04:18] [INFO] testing connection to the target URL\n"
            "[14:04:18] [INFO] checking if the target is protected by some kind of WAF/IPS\n"
            "[14:04:19] [INFO] testing if the target URL content is stable\n"
            "[14:04:19] [INFO] target URL content is stable\n"
            "[14:04:19] [INFO] testing if GET parameter 'id' is dynamic\n"
            "[14:04:20] [INFO] GET parameter 'id' appears to be dynamic\n"
            "[14:04:20] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable\n"
            "[14:04:21] [INFO] testing for SQL injection on GET parameter 'id'\n"
            "[14:04:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n"
            "[14:04:23] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable\n"
            "[14:04:24] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'\n"
            "[14:04:25] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable\n"
            "[14:04:26] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'\n"
            "[14:04:28] [INFO] target URL appears to have 4 columns in query\n"
            "[14:04:30] [INFO] GET parameter 'id' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable\n"
            "GET parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N] N\n"
            "sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: error-based\n"
            "    Payload: id=1 AND (SELECT 5841 FROM (SELECT(SLEEP(0)))xxxx)\n"
            "    Type: UNION query\n"
            "    Payload: id=-1238 UNION ALL SELECT NULL,NULL,CONCAT(0x71,user(),0x71),NULL\n"
            "---\n"
            "[14:04:32] [INFO] fetching database names\n"
            "available databases [4]:\n"
            "[*] information_schema\n"
            "[*] fenneclabs_prod\n"
            "[*] users\n"
            "[*] sessions"
        ),
    }

    state.final_summary = ""
    return state


def main() -> None:
    state = build_scene()
    renderer = DashboardRenderer(state)

    # Render at a fixed width — matches a roomy iTerm window. record=True so
    # we can save the output as SVG (rich's SVG export keeps ANSI styling).
    console = Console(record=True, width=170, force_terminal=True)
    console.print(renderer.render())

    out_dir = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    svg_path = out_dir / "cli-dashboard.svg"
    console.save_svg(str(svg_path), title="Fennec AI — CLI dashboard")
    print(f"  ✓ wrote {svg_path}")

    # PNG is generated outside this script via:
    #     rsvg-convert -w 2200 docs/screenshots/cli-dashboard.svg \
    #         -o docs/screenshots/cli-dashboard.png
    # so this script stays dep-free (no Cairo/Pillow in requirements).


if __name__ == "__main__":
    main()

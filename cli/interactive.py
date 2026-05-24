#!/usr/bin/env python
"""
Fennec AI — Interactive CLI dashboard.

Renders a live, multi-panel terminal view that mirrors the web dashboard's
Live Activity surface: which agent is running, the hypothesis tree, the
latest tool calls, the running findings count by severity. The whole thing
is powered by the same ``agent.run_pentest`` event_sink hook the FastAPI
server uses to push SSE events to the React frontend — so the CLI sees
the exact same firehose the GUI does, just rendered with ``rich`` instead
of TSX.

Two entry points:

    python -m cli.main                       # full interactive prompt + dashboard
    python -m cli.main scan --target URL     # one-shot with live dashboard

Internal use:

    from cli.interactive import run_interactive_scan
    asyncio.run(run_interactive_scan(target=..., method=...))
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── rich UI ────────────────────────────────────────────────────────────────
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree


# ─── Constants ────────────────────────────────────────────────────────────

# Map severity → rich color (matches the orange/red fennec palette so the
# CLI looks like a sibling of the GUI, not a sad text dump).
SEVERITY_STYLE = {
    "critical": "bold red on #2a0000",
    "high":     "bold #ff8c00",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "bold white",
}

AGENT_GLYPH = {
    "orchestrator": "◆",
    "recon":        "🜍",
    "analyst":      "✦",
    "pentester":    "☠",
    "coder":        "λ",
    "devops":       "⚙",
}

AGENT_COLOR = {
    "orchestrator": "#ffb86c",
    "recon":        "#8be9fd",
    "analyst":      "#bd93f9",
    "pentester":    "#ff5555",
    "coder":        "#50fa7b",
    "devops":       "#f1fa8c",
}

# Hypothesis status → marker color (matches the dashboard chips)
STATUS_STYLE = {
    "pending":     ("◇", "white"),
    "in_progress": ("◈", "cyan"),
    "completed":   ("●", "green"),
    "blocked":     ("◌", "magenta"),
    "dead_end":    ("✕", "grey50"),
}


def _strip_for_terminal(text: str, max_len: int = 4000) -> str:
    """Trim huge tool outputs so a runaway ``cat /var/log/...`` doesn't blow
    out the dashboard. We keep the head + a separator + the tail — that's the
    bit a security operator actually wants to read."""
    if len(text) <= max_len:
        return text
    head = max_len // 2 - 64
    tail = max_len // 2 - 64
    return f"{text[:head]}\n... [truncated {len(text) - head - tail} chars] ...\n{text[-tail:]}"


# ─── Live dashboard state ────────────────────────────────────────────────

@dataclass
class DashboardState:
    """Mutable, single-source-of-truth blob the renderer reads on every tick.

    The agent loop's event_sink only mutates this; the rich Live thread only
    reads it. No locks because Python asyncio is single-threaded — both run
    on the same event loop."""

    target: str = ""
    method: str = "balanced"
    started_at: float = field(default_factory=time.time)

    # ── routing ──────────────────────────────────
    current_agent: str = "orchestrator"
    current_node: str = ""

    # ── streams ──────────────────────────────────
    # ring buffer of recent activity for the centre panel
    activity: deque = field(default_factory=lambda: deque(maxlen=14))
    # tool calls in flight (id -> name + args), latest result
    pending_tools: dict = field(default_factory=dict)
    last_tool_call: Optional[dict] = None
    last_tool_result: Optional[dict] = None

    # ── world state snapshots from the graph ────
    hypothesis_tree: dict = field(default_factory=dict)
    pending_queue: list = field(default_factory=list)
    current_hypothesis_id: Optional[str] = None
    findings: list = field(default_factory=list)  # list of finding dicts
    recon_paths: int = 0
    recon_services: int = 0

    # ── terminal state ───────────────────────────
    finished: bool = False
    final_summary: str = ""
    error: Optional[str] = None

    # counts derived from findings — recomputed once per snapshot
    def severity_counts(self) -> Counter:
        c = Counter()
        for f in self.findings:
            sev = (f.get("severity") or "info").lower()
            c[sev] += 1
        return c

    # vulnerable hypotheses from the tree
    def confirmed_vulns(self) -> list:
        out = []
        for h in self.hypothesis_tree.values():
            if not isinstance(h, dict):
                continue
            if (h.get("result") or "").lower() == "vulnerable":
                out.append(h)
        return out


# ─── Rendering ────────────────────────────────────────────────────────────

class DashboardRenderer:
    """Builds the rich Layout from a DashboardState snapshot. Pure rendering —
    never mutates state. Keeping render code out of the event_sink keeps the
    update path fast."""

    def __init__(self, state: DashboardState) -> None:
        self.state = state

    # ─── header ───────────────────────────────────────────────────
    def _header(self) -> Panel:
        s = self.state
        elapsed = time.time() - s.started_at
        mins, secs = divmod(int(elapsed), 60)
        glyph = AGENT_GLYPH.get(s.current_agent, "●")
        color = AGENT_COLOR.get(s.current_agent, "white")

        title = Text()
        title.append("🦊  ", style="bold #ff8c00")
        title.append("FENNEC AI", style="bold #ff8c00")
        title.append("  ·  Live Assessment", style="dim")

        body = Table.grid(expand=True, padding=(0, 2))
        body.add_column(justify="left", ratio=2)
        body.add_column(justify="left", ratio=2)
        body.add_column(justify="right", ratio=1)

        target_cell = Text()
        target_cell.append("target  ", style="dim")
        target_cell.append(s.target or "—", style="bold white")

        agent_cell = Text()
        agent_cell.append("agent  ", style="dim")
        agent_cell.append(f"{glyph} {s.current_agent}", style=f"bold {color}")
        if s.current_node and s.current_node != s.current_agent:
            agent_cell.append(f"  ({s.current_node})", style="dim")

        elapsed_cell = Text()
        elapsed_cell.append("elapsed  ", style="dim")
        elapsed_cell.append(f"{mins:02d}:{secs:02d}", style="bold #ffb86c")
        elapsed_cell.append(f"   method  ", style="dim")
        elapsed_cell.append(s.method, style="bold #50fa7b")

        body.add_row(target_cell, agent_cell, elapsed_cell)

        return Panel(body, title=title, border_style="#ff8c00", padding=(0, 1))

    # ─── hypotheses tree ──────────────────────────────────────────
    def _hypotheses_panel(self) -> Panel:
        s = self.state
        tree_dict = s.hypothesis_tree or {}

        if not tree_dict:
            inner = Align.center(
                Text("waiting for analyst to propose hypotheses…", style="dim italic"),
                vertical="middle",
            )
            return Panel(inner, title="◐ Hypotheses",
                         border_style="#bd93f9", padding=(1, 1))

        # Build a parent-id → children map so we can render the actual tree
        # the analyst constructs (parent_id pointers in each hypothesis).
        children: dict[Optional[str], list[dict]] = {}
        for hid, hyp in tree_dict.items():
            if not isinstance(hyp, dict):
                continue
            children.setdefault(hyp.get("parent_id"), []).append(hyp)
        # Sort each sibling group by priority desc — same as the queue order
        for lst in children.values():
            lst.sort(key=lambda h: -float(h.get("priority", 0.5)))

        root = Tree(
            Text("📋 Attack hypotheses", style="bold #bd93f9"),
            guide_style="dim",
        )

        def add_subtree(parent_node, hyp_list):
            for hyp in hyp_list:
                hid = hyp.get("id", "?")
                status = (hyp.get("status") or "pending").lower()
                result = (hyp.get("result") or "").lower()
                marker, marker_color = STATUS_STYLE.get(status, ("◇", "white"))
                # Confirmed-vulnerable overrides status colour
                if result == "vulnerable":
                    sev = (hyp.get("severity") or "info").lower()
                    marker = "✖"
                    marker_color = {
                        "critical": "bold red",
                        "high":     "bold #ff8c00",
                        "medium":   "bold yellow",
                        "low":      "bold cyan",
                        "info":     "bold white",
                    }.get(sev, "bold red")
                elif result == "safe":
                    marker, marker_color = "✓", "bold green"

                title = hyp.get("title") or "(untitled)"
                label = Text()
                label.append(f"{marker} ", style=marker_color)
                # Highlight the in-flight hypothesis so the operator can see
                # exactly what the pentester is hammering on right now.
                if hid == s.current_hypothesis_id:
                    label.append(title, style="bold reverse #ffb86c")
                else:
                    label.append(title, style="white")
                if result == "vulnerable":
                    sev = (hyp.get("severity") or "info").upper()
                    label.append(f"  [{sev}]", style=SEVERITY_STYLE.get(sev.lower(), "white"))

                node = parent_node.add(label)
                kids = children.get(hid, [])
                if kids:
                    add_subtree(node, kids)

        add_subtree(root, children.get(None, []))

        return Panel(root, title="◐ Hypotheses",
                     subtitle=f"{len(tree_dict)} total · {len(s.pending_queue)} queued",
                     border_style="#bd93f9", padding=(1, 1))

    # ─── activity log ─────────────────────────────────────────────
    def _activity_panel(self) -> Panel:
        s = self.state
        if not s.activity:
            inner = Align.center(
                Text("agents idle — waiting on first event…", style="dim italic"),
                vertical="middle",
            )
            return Panel(inner, title="≡ Live Activity",
                         border_style="#8be9fd", padding=(1, 1))

        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(width=8, no_wrap=True)
        table.add_column(width=12, no_wrap=True)
        table.add_column(ratio=1, overflow="fold")

        for entry in s.activity:
            ts = entry.get("ts", "")
            agent = entry.get("agent", "system")
            kind = entry.get("kind", "")
            msg = entry.get("msg", "")
            color = AGENT_COLOR.get(agent, "white")
            glyph = AGENT_GLYPH.get(agent, "·")
            kind_style = {
                "tool_call":      "bold #ffb86c",
                "tool_result":    "bold #50fa7b",
                "tool_error":     "bold red",
                "agent_message":  f"bold {color}",
                "node_update":    f"bold {color}",
                "hypothesis":     "bold #bd93f9",
                "finding":        "bold #ff5555",
                "result":         "bold #50fa7b",
            }.get(kind, "white")

            table.add_row(
                Text(ts, style="dim"),
                Text(f"{glyph} {agent}", style=color),
                Text(msg, style=kind_style, overflow="fold"),
            )

        return Panel(table, title="≡ Live Activity",
                     subtitle=f"{len(s.activity)} recent events",
                     border_style="#8be9fd", padding=(0, 1))

    # ─── tool output ──────────────────────────────────────────────
    def _tool_panel(self) -> Panel:
        s = self.state
        if not s.last_tool_call and not s.last_tool_result:
            inner = Align.center(
                Text("no tool calls yet…", style="dim italic"),
                vertical="middle",
            )
            return Panel(inner, title="▶ Latest Tool",
                         border_style="#ffb86c", padding=(1, 1))

        sections = []

        if s.last_tool_call:
            tc = s.last_tool_call
            cmd_args = tc.get("args", {})
            # ``terminal`` tool is the common case — pull out the command so
            # operators see "sqlmap -u … --dbs" rather than the wrapping JSON.
            cmd = cmd_args.get("command") if isinstance(cmd_args, dict) else None
            header = Text()
            header.append("call  ", style="dim")
            header.append(tc.get("tool_name", "?"), style="bold #ffb86c")
            agent = tc.get("agent", "")
            if agent:
                header.append(f"  · {agent}", style="dim")
            sections.append(header)
            if cmd:
                sections.append(Syntax(str(cmd), "bash", theme="ansi_dark",
                                       line_numbers=False, word_wrap=True))
            else:
                # Show condensed args as plain text
                arg_preview = str(cmd_args)
                if len(arg_preview) > 220:
                    arg_preview = arg_preview[:220] + " …"
                sections.append(Text(arg_preview, style="white"))

        if s.last_tool_result:
            tr = s.last_tool_result
            ok = tr.get("success", True)
            head = Text()
            head.append("result  ", style="dim")
            head.append(tr.get("tool_name", "?"), style="bold #50fa7b" if ok else "bold red")
            head.append("  ok" if ok else "  err", style="bold green" if ok else "bold red")
            sections.append(head)
            body = _strip_for_terminal(str(tr.get("result") or ""), max_len=1400)
            sections.append(Text(body, style="white", overflow="fold"))

        return Panel(Group(*sections), title="▶ Latest Tool",
                     border_style="#ffb86c", padding=(1, 1))

    # ─── findings ─────────────────────────────────────────────────
    def _findings_panel(self) -> Panel:
        s = self.state
        counts = s.severity_counts()
        total = sum(counts.values())
        confirmed = s.confirmed_vulns()

        # Recon stats line (also lives here so the panel earns its keep
        # before findings start landing)
        stats = Table.grid(padding=(0, 2))
        stats.add_column()
        stats.add_column(justify="right")
        if s.recon_paths or s.recon_services:
            stats.add_row(Text("paths discovered", style="dim"),
                          Text(str(s.recon_paths), style="bold cyan"))
            stats.add_row(Text("services found", style="dim"),
                          Text(str(s.recon_services), style="bold cyan"))
            stats.add_row("", "")

        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts.get(sev, 0)
            label = Text(sev.upper().ljust(8), style=SEVERITY_STYLE.get(sev, "white"))
            value = Text(str(n), style=SEVERITY_STYLE.get(sev, "white") if n else "dim")
            stats.add_row(label, value)

        total_line = Text()
        total_line.append("total findings  ", style="dim")
        total_line.append(str(total), style="bold white")
        total_line.append(f"   confirmed vulns  ", style="dim")
        total_line.append(str(len(confirmed)),
                          style="bold red" if confirmed else "dim")

        body = Group(stats, Text(""), total_line)
        title_color = "#ff5555" if confirmed else "#ffb86c"
        return Panel(body, title="☢ Findings",
                     border_style=title_color, padding=(1, 1))

    # ─── footer / status bar ──────────────────────────────────────
    def _footer(self) -> Panel:
        s = self.state
        if s.finished:
            if s.error:
                msg = Text(f"✕ run failed: {s.error}", style="bold red")
            elif s.confirmed_vulns():
                msg = Text(f"✓ run complete — {len(s.confirmed_vulns())} vulnerabilities confirmed",
                           style="bold #50fa7b")
            else:
                msg = Text("✓ run complete — no confirmed vulnerabilities",
                           style="bold #50fa7b")
        else:
            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.time() * 10) % 10]
            msg = Text()
            msg.append(f"{spinner}  ", style="bold #ff8c00")
            msg.append("agents working — Ctrl+C to abort", style="dim")
        return Panel(Align.center(msg), border_style="dim", padding=(0, 1))

    # ─── compose the layout ───────────────────────────────────────
    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._header(), name="header", size=5),
            Layout(name="middle", ratio=1),
            Layout(self._footer(), name="footer", size=3),
        )
        layout["middle"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="centre", ratio=3),
            Layout(name="right", ratio=2),
        )
        layout["middle"]["left"].split_column(
            Layout(self._hypotheses_panel(), name="hyp", ratio=2),
            Layout(self._findings_panel(), name="find", ratio=1),
        )
        layout["middle"]["centre"].update(self._activity_panel())
        layout["middle"]["right"].update(self._tool_panel())
        return layout


# ─── Event sink: pipes agent events into DashboardState ──────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _shorten(text: str, n: int = 90) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def make_event_sink(state: DashboardState):
    """Build an async callback compatible with ``agent.run_pentest``'s
    ``event_sink`` parameter. Every emitted event mutates ``state`` in place
    so the next renderer tick picks it up."""

    async def sink(event_type: str, data: dict) -> None:
        # node_update: agent transitioned to a different graph node
        if event_type == "node_update":
            agent = data.get("agent", state.current_agent)
            state.current_agent = agent
            state.current_node = data.get("node", "")
            state.activity.append({
                "ts": _ts(), "agent": agent, "kind": "node_update",
                "msg": f"→ entered {data.get('node', agent)}",
            })

        # message: an AIMessage from a graph node
        elif event_type == "message":
            agent = data.get("agent", state.current_agent)
            content = _shorten(str(data.get("content", "")), 110)
            if content:
                state.activity.append({
                    "ts": _ts(), "agent": agent, "kind": "agent_message",
                    "msg": content,
                })

        # tool_call: an AIMessage that wraps tool_calls
        elif event_type == "tool_call":
            tool_name = data.get("tool_name", "?")
            agent = data.get("agent", state.current_agent)
            state.last_tool_call = data
            state.pending_tools[data.get("tool_id", "")] = data
            args = data.get("args", {})
            # terminal tool gets its command highlighted in the log line
            arg_preview = ""
            if isinstance(args, dict):
                if args.get("command"):
                    arg_preview = _shorten(str(args["command"]), 80)
                elif args.get("url"):
                    arg_preview = _shorten(str(args["url"]), 80)
                else:
                    arg_preview = _shorten(str(args), 80)
            state.activity.append({
                "ts": _ts(), "agent": agent, "kind": "tool_call",
                "msg": f"⮞ {tool_name}({arg_preview})" if arg_preview else f"⮞ {tool_name}()",
            })

        # tool_execution: the matching ToolMessage
        elif event_type == "tool_execution":
            tool_name = data.get("tool_name", "?")
            agent = data.get("agent", state.current_agent)
            ok = data.get("success", True)
            state.last_tool_result = data
            result_preview = _shorten(str(data.get("result", "")), 100)
            state.activity.append({
                "ts": _ts(), "agent": agent,
                "kind": "tool_result" if ok else "tool_error",
                "msg": f"← {tool_name}: {result_preview}",
            })

        # hypothesis_tree snapshot — replace wholesale
        elif event_type == "hypothesis_tree":
            mgr = data.get("hypothesis_manager") or {}
            tree = mgr.get("tree") or {}
            state.hypothesis_tree = tree
            state.pending_queue = mgr.get("pending_queue") or []
            # log a hypothesis-count delta-ish line so the centre panel
            # acknowledges the analyst's work
            n = len(tree)
            state.activity.append({
                "ts": _ts(), "agent": "analyst", "kind": "hypothesis",
                "msg": f"hypothesis tree updated — {n} hypotheses in flight",
            })

        # current_hypothesis: highlight in tree
        elif event_type == "current_hypothesis":
            state.current_hypothesis_id = data.get("hypothesis_id")

        # findings_update — correlation store snapshot
        elif event_type == "findings_update":
            corr = data.get("correlation_store") or {}
            findings_map = corr.get("findings") or {}
            old_count = len(state.findings)
            state.findings = list(findings_map.values())
            new_count = len(state.findings)
            if new_count > old_count:
                latest = state.findings[-1]
                sev = (latest.get("severity") or "info").upper()
                state.activity.append({
                    "ts": _ts(), "agent": state.current_agent, "kind": "finding",
                    "msg": f"⚑ new finding — [{sev}] {_shorten(latest.get('title', ''), 60)}",
                })

        # recon_update — summarise path/service counts so the Findings panel
        # has something to show before any vulns land
        elif event_type == "recon_update":
            recon = data.get("recon_data") or {}
            # recon shape varies: try to count common keys
            paths = recon.get("paths") or recon.get("discovered_paths") or []
            services = recon.get("services") or recon.get("ports") or []
            if isinstance(paths, list):
                state.recon_paths = len(paths)
            elif isinstance(paths, dict):
                state.recon_paths = len(paths)
            if isinstance(services, list):
                state.recon_services = len(services)
            elif isinstance(services, dict):
                state.recon_services = len(services)
            state.activity.append({
                "ts": _ts(), "agent": "recon", "kind": "agent_message",
                "msg": f"recon snapshot: {state.recon_paths} paths · {state.recon_services} services",
            })

        # result — final agent summary
        elif event_type == "result":
            state.final_summary = str(data.get("final_result", ""))
            state.activity.append({
                "ts": _ts(), "agent": "orchestrator", "kind": "result",
                "msg": f"final report: {_shorten(state.final_summary, 90)}",
            })

    return sink


# ─── Final summary screen ────────────────────────────────────────────────

def render_final_summary(state: DashboardState, console: Console) -> None:
    """After the Live context closes, dump a static, scrollable summary
    panel so the operator can copy/paste findings without fighting the
    live renderer."""
    confirmed = state.confirmed_vulns()

    console.print()
    if state.error:
        console.print(Panel(
            Text(state.error, style="bold red"),
            title="✕ run failed",
            border_style="red",
        ))
        return

    # Findings table
    counts = state.severity_counts()
    summary_table = Table(title="Findings by severity", title_style="bold #ff8c00",
                          show_header=False, border_style="dim", expand=False)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            summary_table.add_row(Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white")),
                                  Text(str(n), style="bold white"))
    if not counts:
        summary_table.add_row(Text("none", style="dim"), Text("0", style="dim"))

    elapsed = time.time() - state.started_at
    mins, secs = divmod(int(elapsed), 60)
    meta = Table.grid(padding=(0, 3))
    meta.add_column()
    meta.add_column(style="bold white")
    meta.add_row(Text("Target", style="dim"), state.target)
    meta.add_row(Text("Method", style="dim"), state.method)
    meta.add_row(Text("Duration", style="dim"), f"{mins:02d}:{secs:02d}")
    meta.add_row(Text("Confirmed vulnerabilities", style="dim"),
                 Text(str(len(confirmed)),
                      style="bold red" if confirmed else "bold green"))

    console.print(Panel(Group(meta, Text(""), summary_table),
                        title="🦊 Assessment Complete",
                        border_style="#ff8c00", padding=(1, 2)))

    # Confirmed vuln cards
    if confirmed:
        for hyp in confirmed:
            sev = (hyp.get("severity") or "info").lower()
            sev_style = SEVERITY_STYLE.get(sev, "white")
            header = Text()
            header.append(f"[{sev.upper()}] ", style=sev_style)
            header.append(hyp.get("title", "(untitled)"), style="bold white")
            desc = hyp.get("description", "") or "(no description)"
            owasp = hyp.get("owasp_category", "")
            footer = Text()
            if owasp:
                footer.append(f"OWASP {owasp}", style="dim")
            console.print(Panel(
                Group(Text(desc, style="white"), Text(""), footer),
                title=header,
                border_style=sev_style.split()[-1] if "on" not in sev_style else "red",
                padding=(1, 2),
            ))

    if state.final_summary:
        console.print(Panel(
            Text(state.final_summary, style="white"),
            title="📋 Orchestrator summary",
            border_style="#ffb86c", padding=(1, 2),
        ))


# ─── Entry point ──────────────────────────────────────────────────────────

async def run_interactive_scan(
    target: Optional[str] = None,
    method: str = "balanced",
    description: Optional[str] = None,
    htli: bool = False,
    refresh_per_second: float = 6.0,
) -> int:
    """Prompt for missing args, then run a pentest with the live dashboard.

    Returns the integer exit code (0 on success, 1 on error)."""
    console = Console()

    # Lazy import so `cli/main.py --help` doesn't fault when the heavy
    # langchain dependency graph hasn't been installed yet.
    from agent import PentestTask, PentestMode, run_pentest

    # ── Interactive prompts ─────────────────────────────────────
    if not target:
        console.print()
        console.print(Panel(
            Text("Interactive penetration test — answer the prompts to start.\n"
                 "All fields support defaults; just hit Enter to accept.",
                 style="white"),
            title="🦊  Fennec AI — Interactive scan",
            border_style="#ff8c00", padding=(1, 2),
        ))
        target = Prompt.ask(
            Text("Target URL", style="bold #ff8c00"),
            default="http://localhost:8080",
            console=console,
        )

    if not description:
        description = Prompt.ask(
            Text("Objective", style="bold #ff8c00"),
            default="Identify and exploit vulnerabilities in the target",
            console=console,
        )

    if method == "balanced":
        method = Prompt.ask(
            Text("Method", style="bold #ff8c00"),
            choices=["turbo", "balanced", "deep"],
            default="balanced",
            console=console,
        )

    # The graph reads method from env — same hand-off the API uses
    os.environ["FENNEC_METHOD"] = method

    # ── Build task ──────────────────────────────────────────────
    task = PentestTask(
        target_url=target,
        description=description,
        mode=PentestMode.BLACK_BOX,
    )

    state = DashboardState(target=target, method=method)
    sink = make_event_sink(state)
    renderer = DashboardRenderer(state)

    # Seed a friendly first event so the activity log isn't blank on first paint
    state.activity.append({
        "ts": _ts(), "agent": "orchestrator", "kind": "node_update",
        "msg": f"⚑ starting {method} assessment of {target}",
    })

    # ── Run the agent under the Live context ────────────────────
    agent_task: Optional[asyncio.Task] = None
    try:
        with Live(renderer.render(), console=console, refresh_per_second=refresh_per_second,
                  screen=False, transient=False) as live:

            # Run the pentest in a background task so we can repaint the
            # live view while it runs. The event_sink callback mutates the
            # shared DashboardState — repaint is just rendering fresh.
            async def run_agent():
                return await run_pentest(task, verbose=False, htli=htli,
                                         event_sink=sink)

            agent_task = asyncio.create_task(run_agent())

            # Repaint until the agent finishes
            while not agent_task.done():
                live.update(renderer.render())
                await asyncio.sleep(1.0 / refresh_per_second)

            # One final paint so the last event shows up
            live.update(renderer.render())

            result = await agent_task
            state.finished = True
            state.error = result.error
            # Mirror result.vulnerabilities into final summary if not already set
            if not state.final_summary and result.final_summary:
                state.final_summary = result.final_summary
            live.update(renderer.render())

    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]aborted by user[/yellow]")
        if agent_task and not agent_task.done():
            agent_task.cancel()
            try:
                await agent_task
            except Exception:
                pass
        state.error = "aborted by user"
        state.finished = True

    # ── Static final summary ────────────────────────────────────
    render_final_summary(state, console)

    return 0 if not state.error else 1


# ─── Allow running as a module for ad-hoc testing ─────────────────────────

def _maybe_load_env() -> None:
    """Find .env relative to this file so the user can `python -m cli.interactive`
    from anywhere."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    here = Path(__file__).resolve().parent.parent
    env = here / ".env"
    if env.exists():
        load_dotenv(env, override=False)


if __name__ == "__main__":
    _maybe_load_env()
    # Ensure project root is on path so `agent` import resolves
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    rc = asyncio.run(run_interactive_scan())
    sys.exit(rc)

# Contributing to Fennec

Thanks for your interest in improving Fennec! Issues and pull requests are welcome.

## Ground rules

- **Authorized testing only.** Fennec is an offensive-security tool. Never use it,
  or contribute features designed to be used, against systems without explicit
  authorization.
- **OSS stays vendor-neutral.** Don't add proprietary services, telemetry, or auth
  gates. The hosted product ([fenneclabs.ai](https://fenneclabs.ai)) lives elsewhere.
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Dev setup

```bash
git clone https://github.com/Fennec-AI/Fennec.git
cd Fennec

# Python (3.11+)
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]      # runtime deps + ruff + pytest

# Frontend
cd frontend && npm install && cd ..
```

You'll need an LLM API key in `.env` (copy `.env.example`) and Docker to run real
scans, but the test suite and lint run without either.

## Before opening a PR

Run the same checks CI runs:

```bash
ruff check .                 # lint (Python)
pytest                       # offline test suite
npm --prefix frontend run lint
npm --prefix frontend run build
```

- New tools go in `src/tools/` with a Pydantic input schema.
- New agents need an `AgentType` entry, a router branch in `src/graph/`, and a
  prompt in `src/prompts/`.
- Update `CHANGELOG.md` (under `## [Unreleased]`) and any affected docs when you
  change behavior or configuration.
- Keep PRs focused. A short description of *what* and *why* goes a long way.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [CLAUDE.md](CLAUDE.md) for the
state schema, the LangGraph wiring, the middleware chain, and the method presets.

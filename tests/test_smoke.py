"""Offline smoke tests.

These run without network access, Docker, or any LLM API key — they exercise
the import graph, the LangGraph build, and a couple of stable defaults so a
fresh clone gets a green `pytest` out of the box.
"""

import importlib

import pytest


def test_role_based_graph_compiles():
    """The full agent graph wires up and compiles."""
    from src.graph.role_based_graph import compile_role_based_graph

    assert compile_role_based_graph() is not None


def test_default_model_is_current_sonnet():
    """The shipped default model is the current Claude Sonnet 4.6.

    Checked against the field default directly so a local .env can't skew it.
    """
    from src.config.settings import FennecConfig

    assert FennecConfig.model_fields["llm_model"].default == "claude-sonnet-4-6"


@pytest.mark.parametrize(
    "module",
    [
        "src.agents.recon",
        "src.agents.analyst",
        "src.agents.pentester",
        "src.agents.coder",
        "src.tools.hypothesis_tools",
        "src.api.server",
        "src.api.demo_seed",
    ],
)
def test_key_modules_import(module):
    """Core modules import cleanly (guards the try/except import fallbacks)."""
    assert importlib.import_module(module) is not None

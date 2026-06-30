"""Pytest bootstrap.

Put the repository root on sys.path so tests can ``import src.*`` no matter how
pytest is invoked (bare ``pytest`` vs ``python -m pytest``). pytest imports this
root conftest before collecting any tests.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

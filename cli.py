#!/usr/bin/env python
"""
Entry point for Fennec AI CLI.

Note on sys.path ordering: we insert THIS project's directory at position 0
so `from cli.main import main` resolves to *our* `cli/main.py` even when
the user's parent directory happens to contain another `cli/` package
(common when fennec-oss lives inside a larger checkout). Without this the
wrong `cli.main` can win and import-fail with a `fennec_ai`-shaped error.
"""
import sys
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from cli.main import main

if __name__ == "__main__":
    main()

"""Compatibility import for pipeline debugging helpers.

The implementation lives in ``scripts.debug_pipeline``. This wrapper keeps
existing root-level imports working after the project layout moved scripts into
the ``scripts`` package.
"""

from scripts.debug_pipeline import *  # noqa: F401,F403

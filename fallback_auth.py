"""Compatibility import for fallback authentication helpers.

The implementation lives in ``scripts.fallback_auth``. This wrapper keeps older
project imports working from tests, benchmarks, and API utilities.
"""

from scripts.fallback_auth import *  # noqa: F401,F403

"""conftest.py — Shared pytest fixtures for SUMIT KEY test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear per-IP rate-limit counters before every test.

    TestClient uses 'testclient' as the host IP. Without this reset the
    per-minute rate limit (10 req/min) is exhausted after the first 10
    tests that hit the API, causing all subsequent tests to get 429.
    """
    import security

    # Use the module-level singleton set when RateLimitMiddleware is first
    # instantiated in api.py.  Importing api triggers that instantiation.
    import api as _  # noqa: F401 — side-effect: sets security._rate_limiter_instance

    rl = security._rate_limiter_instance
    if rl is not None:
        with rl.lock:
            rl.request_times.clear()

    security.threat_logger.ip_violation_count.clear()
    security.threat_logger.ip_last_threat.clear()

    yield

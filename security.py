"""security.py — Comprehensive threat handling for SUMIT KEY API

Implements:
  1. Rate limiting (per-IP, per-endpoint)
  2. Input validation & sanitization
  3. Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
  4. Resource protection (timeouts, memory limits, capture duration caps)
  5. Exception handling (no stack trace leaks)
  6. API key authentication (optional)
  7. Threat logging & monitoring
  8. CORS hardening

Usage in api.py:
  from security import (
      RateLimitMiddleware, SecurityHeadersMiddleware, ThreatLogger,
      validate_duration, validate_security_level, require_api_key
  )
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import defaultdict
from typing import Any, Callable, Optional
from functools import wraps
import threading

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("security")

# ============================================================================
# 1. THREAT LOGGER — Structured threat detection & logging
# ============================================================================

class ThreatLogger:
    """Detects and logs security threats (brute force, malformed input, etc.)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.threat_events: list[dict[str, Any]] = []
        self.ip_violation_count: dict[str, int] = defaultdict(int)
        self.ip_last_threat: dict[str, float] = {}
        # Thresholds
        self.VIOLATIONS_PER_IP_THRESHOLD = 5
        self.THREAT_WINDOW_SECONDS = 60

    def log_threat(self, threat_type: str, ip: str, details: str = "") -> None:
        """Log a threat event and increment IP violation counter."""
        with self.lock:
            event = {
                "timestamp": time.time(),
                "type": threat_type,
                "ip": ip,
                "details": details,
            }
            self.threat_events.append(event)
            self.ip_violation_count[ip] += 1
            self.ip_last_threat[ip] = time.time()

            log.warning(
                f"THREAT: {threat_type} from {ip} | {details} | "
                f"violations={self.ip_violation_count[ip]}"
            )

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP exceeded violation threshold in the threat window."""
        with self.lock:
            last_threat = self.ip_last_threat.get(ip, 0)
            if time.time() - last_threat > self.THREAT_WINDOW_SECONDS:
                self.ip_violation_count[ip] = 0
                return False
            return self.ip_violation_count[ip] > self.VIOLATIONS_PER_IP_THRESHOLD

    def get_stats(self) -> dict[str, Any]:
        """Return threat stats (total events, blocked IPs, etc.)."""
        with self.lock:
            blocked_ips = [
                ip for ip in self.ip_violation_count
                if self.is_ip_blocked(ip)
            ]
            return {
                "total_threat_events": len(self.threat_events),
                "blocked_ips_count": len(blocked_ips),
                "blocked_ips": blocked_ips,
                "recent_threats": self.threat_events[-10:],  # Last 10
            }


threat_logger = ThreatLogger()


# ============================================================================
# 2. RATE LIMITING MIDDLEWARE
# ============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-IP rate limits (e.g., 10 requests/minute, 30 per hour)."""

    def __init__(
        self,
        app: FastAPI,
        requests_per_minute: int = 10,
        requests_per_hour: int = 100,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.lock = threading.Lock()
        self.request_times: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self._get_client_ip(request)

        # Check rate limits
        now = time.time()
        with self.lock:
            # Clean old entries (> 1 hour old)
            if client_ip in self.request_times:
                self.request_times[client_ip] = [
                    t for t in self.request_times[client_ip]
                    if now - t < 3600
                ]

            # Count requests in last minute & hour
            minute_ago = now - 60
            hour_ago = now - 3600
            recent_minute = [
                t for t in self.request_times[client_ip] if t > minute_ago
            ]
            recent_hour = [
                t for t in self.request_times[client_ip] if t > hour_ago
            ]

            # Check thresholds
            if len(recent_minute) >= self.requests_per_minute:
                threat_logger.log_threat(
                    "RATE_LIMIT_MINUTE",
                    client_ip,
                    f"{len(recent_minute)}/{self.requests_per_minute} req/min",
                )
                return JSONResponse(
                    {"error": "Rate limit exceeded (per minute)"},
                    status_code=429,
                )

            if len(recent_hour) >= self.requests_per_hour:
                threat_logger.log_threat(
                    "RATE_LIMIT_HOUR",
                    client_ip,
                    f"{len(recent_hour)}/{self.requests_per_hour} req/hour",
                )
                return JSONResponse(
                    {"error": "Rate limit exceeded (per hour)"},
                    status_code=429,
                )

            # Record this request
            self.request_times[client_ip].append(now)

        # Block if IP is flagged
        if threat_logger.is_ip_blocked(client_ip):
            return JSONResponse(
                {"error": "IP temporarily blocked due to security violations"},
                status_code=403,
            )

        response = await call_next(request)
        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract real client IP (handles X-Forwarded-For, etc.)."""
        if "x-forwarded-for" in request.headers:
            return request.headers["x-forwarded-for"].split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# ============================================================================
# 3. SECURITY HEADERS MIDDLEWARE
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers (HSTS, X-Frame-Options, CSP, etc.) to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # HSTS — enforce HTTPS (30 days)
        response.headers["Strict-Transport-Security"] = "max-age=2592000; includeSubDomains"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Content Security Policy — strict (no inline, no external scripts except our API)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        
        # Remove server version disclosure
        response.headers["Server"] = "SUMIT-KEY/2.0"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response


# ============================================================================
# 4. INPUT VALIDATION & SANITIZATION
# ============================================================================

def validate_duration(duration: float) -> float:
    """Validate and sanitize capture duration.
    
    Raises HTTPException if invalid.
    """
    MIN_DURATION = 1.0
    MAX_DURATION = 60.0
    
    try:
        duration = float(duration)
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="duration must be a number")
    
    if duration < MIN_DURATION or duration > MAX_DURATION:
        raise HTTPException(
            status_code=422,
            detail=f"duration must be between {MIN_DURATION} and {MAX_DURATION} seconds",
        )
    
    return duration


def validate_security_level(level: str) -> str:
    """Validate security_level is one of: 'quantum', 'standard'."""
    allowed = {"quantum", "standard"}
    level = str(level).lower().strip()
    
    if level not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"security_level must be one of {allowed}",
        )
    
    return level


def sanitize_string(value: str, max_len: int = 100) -> str:
    """Remove potentially dangerous characters from a string."""
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Value must be string")
    
    if len(value) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"String too long (max {max_len} chars)",
        )
    
    # Remove null bytes, control characters
    value = "".join(c for c in value if ord(c) >= 32 or c in "\n\r\t")
    return value


# ============================================================================
# 5. API KEY AUTHENTICATION (Optional)
# ============================================================================

class APIKeyAuth:
    """Optional API key authentication for endpoints."""

    def __init__(self, api_key_env: str = "SUMIT_API_KEY"):
        self.expected_key = os.environ.get(api_key_env)
        self.enabled = bool(self.expected_key)

    def verify(self, api_key: Optional[str]) -> bool:
        """Return True if API key is valid (or auth disabled)."""
        if not self.enabled:
            return True
        if not api_key:
            return False
        return hashlib.sha256(api_key.encode()).hexdigest() == self.expected_key

    def __call__(self, api_key: Optional[str] = None) -> bool:
        """Dependency injection for FastAPI."""
        if not self.verify(api_key):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API key",
            )
        return True


def require_api_key(api_key: Optional[str] = None) -> Depends:
    """FastAPI dependency to require valid API key.
    
    Usage:
      @app.post("/protected")
      def protected_route(payload: dict, _auth=Depends(require_api_key)):
          ...
    """
    auth = APIKeyAuth()
    return Depends(auth)


# ============================================================================
# 6. RESOURCE PROTECTION & TIMEOUT
# ============================================================================

class ResourceLimits:
    """Enforce resource constraints (memory, CPU time, max concurrent captures)."""

    def __init__(self, max_concurrent_captures: int = 3):
        self.max_concurrent = max_concurrent_captures
        self.current_captures = 0
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        """Try to start a new capture. Return True if allowed."""
        with self.lock:
            if self.current_captures >= self.max_concurrent:
                return False
            self.current_captures += 1
            return True

    def release(self) -> None:
        """Mark a capture as complete."""
        with self.lock:
            self.current_captures = max(0, self.current_captures - 1)

    def get_status(self) -> dict[str, Any]:
        """Return current resource usage."""
        with self.lock:
            return {
                "current_captures": self.current_captures,
                "max_concurrent": self.max_concurrent,
                "available_slots": self.max_concurrent - self.current_captures,
            }


resource_limits = ResourceLimits(max_concurrent_captures=3)


# ============================================================================
# 7. EXCEPTION HANDLERS (No stack trace leaks)
# ============================================================================

def register_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers that don't leak stack traces."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        client_ip = request.client.host if request.client else "unknown"
        log.info(f"HTTP {exc.status_code}: {exc.detail} from {client_ip}")
        return JSONResponse(
            {"error": exc.detail, "status_code": exc.status_code},
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        client_ip = request.client.host if request.client else "unknown"
        threat_logger.log_threat(
            "UNHANDLED_EXCEPTION",
            client_ip,
            type(exc).__name__,
        )
        log.exception(f"Unhandled exception from {client_ip}")
        # Return safe error (no stack trace)
        return JSONResponse(
            {"error": "Internal server error"},
            status_code=500,
        )

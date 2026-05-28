# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""Self-healing recovery layer for SUMIT KEY encryption operations.

The healer protects the middle of the message/file encryption flow:

1. Write an append-only journal checkpoint before each important stage.
2. Encrypt with the 0.3-second rotating-key envelope.
3. Immediately verify that the envelope can decrypt under the same context.
4. If a transient fault occurs, retry in a fresh epoch.
5. If the primary identity is unavailable, fail over to a backup identity.
6. If all recovery paths fail, mark the operation failed closed.

The healer never bypasses authentication, threat blocks, AES-GCM tag failures,
or identity mismatches. Those are security decisions, not transient faults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag

from advanced_security import (
    ExpiredKeyEpochError,
    RotatingEncryptedMessage,
    RotatingKeyEnvelope,
    SystemIdentity,
    ThreatBlockedError,
)


class SelfHealingError(Exception):
    """Raised when an operation cannot be safely recovered."""


class UnrecoverableSecurityError(SelfHealingError):
    """Raised when recovery would bypass a real security control."""


@dataclass(frozen=True)
class HealingEvent:
    """One auditable recovery checkpoint."""

    operation_id: str
    stage: str
    status: str
    detail: str
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class HealingResult:
    """Final result of a healed encryption operation."""

    operation_id: str
    status: str
    active_path: str
    attempts: int
    envelope: RotatingEncryptedMessage
    events: tuple[HealingEvent, ...]
    recovered: bool
    rollback_performed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "active_path": self.active_path,
            "attempts": self.attempts,
            "recovered": self.recovered,
            "rollback_performed": self.rollback_performed,
            "envelope": self.envelope.to_dict(),
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True)
class SelfHealingConfig:
    """Tuning knobs for recovery."""

    max_retries: int = 2
    retry_backoff_seconds: float = 0.01
    verify_after_encrypt: bool = True
    journal_path: Path | None = None
    allow_backup_identity: bool = True
    max_verify_clock_skew_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds must be >= 0")
        if self.max_verify_clock_skew_seconds < 0:
            raise ValueError("max_verify_clock_skew_seconds must be >= 0")


@dataclass
class SelfHealingCryptoService:
    """Run rotating encryption with journaled recovery and failover."""

    primary_identity: SystemIdentity
    backup_identity: SystemIdentity | None = None
    config: SelfHealingConfig = field(default_factory=SelfHealingConfig)
    clock: Callable[[], float] | None = None

    def encrypt_message(
        self,
        plaintext: str | bytes,
        *,
        context: str = "message",
        operation_id: str | None = None,
        mouse_events: list[dict[str, Any]] | None = None,
        message_id: str | None = None,
        source_ip: str = "local",
        failed_otp_attempts: int = 0,
        nfc_required_but_missing: bool = False,
        failpoints: set[str] | None = None,
    ) -> HealingResult:
        """Encrypt with automatic recovery from transient middle failures.

        ``failpoints`` is intentionally exposed for black-box/sandbox tests.
        Supported values:
          - ``primary_encrypt``: simulate primary path outage before encrypt.
          - ``verify_once``: simulate a one-time verification outage.
          - ``always_verify``: simulate verification outage on every attempt.
        """

        op_id = operation_id or os.urandom(12).hex()
        events: list[HealingEvent] = []
        triggered_failpoints: set[str] = set()
        total_attempts = 0
        last_error: Exception | None = None

        self._record(events, op_id, "preflight", "ok", "journal and identity ready")

        paths: list[tuple[str, SystemIdentity]] = [("primary", self.primary_identity)]
        if self.config.allow_backup_identity and self.backup_identity is not None:
            paths.append(("backup", self.backup_identity))

        for path_name, identity in paths:
            for attempt in range(self.config.max_retries + 1):
                total_attempts += 1
                self._record(
                    events,
                    op_id,
                    f"{path_name}.attempt",
                    "start",
                    f"attempt {attempt + 1}",
                )
                try:
                    if (
                        path_name == "primary"
                        and failpoints
                        and "primary_encrypt" in failpoints
                    ):
                        raise RuntimeError("simulated primary encryption outage")

                    envelope = RotatingKeyEnvelope(identity, clock=self.clock)
                    encrypted = envelope.encrypt(
                        plaintext,
                        context=context,
                        mouse_events=mouse_events,
                        message_id=message_id,
                        source_ip=source_ip,
                        failed_otp_attempts=failed_otp_attempts,
                        nfc_required_but_missing=nfc_required_but_missing,
                    )
                    self._record(events, op_id, f"{path_name}.encrypt", "ok", "ciphertext created")

                    if self.config.verify_after_encrypt:
                        self._maybe_fail_verify(failpoints or set(), triggered_failpoints)
                        recovered_plaintext = envelope.decrypt(
                            encrypted,
                            context=context,
                            max_clock_skew_seconds=self.config.max_verify_clock_skew_seconds,
                        )
                        expected = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
                        if recovered_plaintext != expected:
                            raise InvalidTag("verification plaintext mismatch")
                        self._record(events, op_id, f"{path_name}.verify", "ok", "decrypt check passed")

                    recovered = path_name != "primary" or attempt > 0
                    if recovered:
                        self._record(events, op_id, "heal", "ok", f"recovered on {path_name}")
                    self._record(events, op_id, "commit", "ok", "operation committed")
                    return HealingResult(
                        operation_id=op_id,
                        status="ok",
                        active_path=path_name,
                        attempts=total_attempts,
                        envelope=encrypted,
                        events=tuple(events),
                        recovered=recovered,
                    )
                except (ThreatBlockedError, InvalidTag, ValueError) as exc:
                    self._record(
                        events,
                        op_id,
                        f"{path_name}.security_stop",
                        "blocked",
                        type(exc).__name__,
                    )
                    self._record(events, op_id, "rollback", "ok", "failed closed")
                    raise UnrecoverableSecurityError(str(exc)) from exc
                except ExpiredKeyEpochError as exc:
                    last_error = exc
                    self._record(
                        events,
                        op_id,
                        f"{path_name}.expired",
                        "retryable",
                        str(exc),
                    )
                    self._sleep_before_retry()
                except Exception as exc:  # transient outage, process interruption, IO hiccup
                    last_error = exc
                    self._record(
                        events,
                        op_id,
                        f"{path_name}.fault",
                        "retryable",
                        f"{type(exc).__name__}: {exc}",
                    )
                    self._sleep_before_retry()

        self._record(events, op_id, "rollback", "ok", "no recovery path succeeded")
        raise SelfHealingError(f"self-healing failed after {total_attempts} attempts: {last_error}")

    def resume_status(self, operation_id: str) -> dict[str, Any]:
        """Read journal entries for one operation."""

        events = [
            event
            for event in self._read_journal()
            if event.get("operation_id") == operation_id
        ]
        return {
            "operation_id": operation_id,
            "events": events,
            "last_status": events[-1]["status"] if events else "unknown",
            "last_stage": events[-1]["stage"] if events else "unknown",
            "event_count": len(events),
        }

    def _record(
        self,
        events: list[HealingEvent],
        operation_id: str,
        stage: str,
        status: str,
        detail: str,
    ) -> None:
        event = HealingEvent(
            operation_id=operation_id,
            stage=stage,
            status=status,
            detail=detail,
            timestamp=self._now(),
        )
        events.append(event)
        self._append_journal(event)

    def _append_journal(self, event: HealingEvent) -> None:
        if self.config.journal_path is None:
            return
        journal = Path(self.config.journal_path)
        journal.parent.mkdir(parents=True, exist_ok=True)
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True))
            handle.write("\n")

    def _read_journal(self) -> list[dict[str, Any]]:
        if self.config.journal_path is None:
            return []
        journal = Path(self.config.journal_path)
        if not journal.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in journal.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entries.append(json.loads(line))
        return entries

    def _maybe_fail_verify(self, failpoints: set[str], triggered_failpoints: set[str]) -> None:
        if "always_verify" in failpoints:
            raise RuntimeError("simulated persistent verification outage")
        if "verify_once" in failpoints and "verify_once" not in triggered_failpoints:
            triggered_failpoints.add("verify_once")
            raise RuntimeError("simulated one-time verification outage")

    def _sleep_before_retry(self) -> None:
        if self.config.retry_backoff_seconds:
            time.sleep(self.config.retry_backoff_seconds)

    def _now(self) -> float:
        return self.clock() if self.clock is not None else time.time()

"""Exception taxonomy for the M1 harness (leaf module: no internal imports)."""

from __future__ import annotations


class GovernanceViolation(Exception):
    """Raised when a stage or component attempts to exceed its authority."""


class IntegrityViolation(GovernanceViolation):
    """Raised when preserved artifacts no longer match their recorded hashes."""


class ContractViolation(GovernanceViolation):
    """Raised when a stage response violates its structured output contract."""


class ModelFailure(Exception):
    """Recoverable model/API failure; consumes retry budget."""


class StageTimeout(Exception):
    """Stage exceeded its enforced wall-clock limit; consumes retry budget."""


class InfrastructureError(Exception):
    """Non-retryable harness-side failure."""


class ProtocolError(InfrastructureError):
    """Malformed worker protocol/usage metrics; never retried as model failure."""

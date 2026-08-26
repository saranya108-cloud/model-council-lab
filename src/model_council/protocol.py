"""Harness subprocess protocol: version handshake and adapter execution profiles.

The runner selects an execution profile from a trusted adapter-kind registry
before invocation. Providers, models, and response shapes cannot choose it.
"""

from __future__ import annotations

from .types import ProtocolError

HARNESS_PROTOCOL_VERSION = "m1-dev-harness-v11"

EXECUTION_PROFILE_PRE_LIVE_LEGACY = "pre_live_legacy"
EXECUTION_PROFILE_LIVE_CONTRACT_V1 = "live_contract_v1"

SUPPORTED_EXECUTION_PROFILES = frozenset(
    {EXECUTION_PROFILE_PRE_LIVE_LEGACY, EXECUTION_PROFILE_LIVE_CONTRACT_V1}
)

# Trusted harness registration: adapter kind → execution profile.
# This is the sole source of compatibility vs live-contract selection.
ADAPTER_KIND_PROFILES: dict[str, str] = {
    "fake": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "introspect": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "tamper": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "sleep": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "rogue": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "crash_worker": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "drift": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "bad_usage": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    "raw_garbage": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    # Deterministic live-protocol stub. Not a provider implementation.
    "live_stub": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
}


def execution_profile_for_kind(kind: str) -> str:
    """Return the harness-registered profile for an adapter kind.

    Unknown kinds fail closed. The mapping is never taken from adapter output.
    """
    if type(kind) is not str or not kind:
        raise ProtocolError("adapter kind must be a non-empty string")
    profile = ADAPTER_KIND_PROFILES.get(kind)
    if profile not in SUPPORTED_EXECUTION_PROFILES:
        raise ProtocolError(f"unknown adapter execution profile for kind {kind!r}")
    return profile

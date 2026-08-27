"""Runner-owned retry eligibility for provider-neutral failures.

Adapters may classify a provider-specific failure into a NeutralError category
and may report observational provider guidance (`provider_retry_hint`,
`retry_after_seconds`). They must not decide that another attempt will occur.

The authoritative mapping from neutral category → retry candidate lives here.
ExperimentRunner still independently checks remaining attempts, the cumulative
stage deadline, and the cumulative input ceiling before authorizing a call.
"""

from __future__ import annotations

from .live_contract import ProviderErrorCategory

RETRYABLE_PROVIDER_CATEGORIES = frozenset(
    {
        ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
        ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
        ProviderErrorCategory.RATE_LIMIT,
        ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
    }
)

NONRETRYABLE_PROVIDER_CATEGORIES = frozenset(
    {
        ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
        ProviderErrorCategory.PERMISSION,
        ProviderErrorCategory.MODEL_UNAVAILABLE,
        ProviderErrorCategory.INVALID_REQUEST,
        ProviderErrorCategory.QUOTA_EXHAUSTED,
        ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
        ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
        ProviderErrorCategory.POLICY_REFUSAL,
        ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
    }
)


def is_retry_candidate(category: ProviderErrorCategory) -> bool:
    """Return whether `category` is on the frozen runner retry allowlist.

    Provider retry hints are intentionally not parameters. Hints cannot change
    this mapping. Classification is total: every enum member must appear in
    exactly one mapping.
    """
    if not isinstance(category, ProviderErrorCategory):
        raise TypeError(f"category must be ProviderErrorCategory, got {type(category).__name__}")
    if category in RETRYABLE_PROVIDER_CATEGORIES:
        return True
    if category in NONRETRYABLE_PROVIDER_CATEGORIES:
        return False
    raise RuntimeError(f"unclassified provider error category: {category!r}")

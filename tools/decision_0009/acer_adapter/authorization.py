"""Pinned offline Chair enrollment verification; no execution capabilities.

Trusted test bootstrap selects a sealed root before constructing a runtime.
This models offline enrollment, not signatures or protected Chair identity.
Runtime requests cannot enroll bytes or choose/replace the service's root.
"""

from dataclasses import asdict, dataclass
import hashlib
import json

from .contracts import (
    AUTHORIZATION_V2_SCHEMA, Authorization, ContractError, OfflineChairTrustRoot,
    authorization_digest, canonical_authorization_bytes,
)


class OfflineChairAuthenticationError(ContractError):
    pass


@dataclass(frozen=True)
class OfflineChairAuthenticationResult:
    root_id: str
    root_version: int
    store_identity: str
    campaign_id: str
    authorization_id: str
    authorization_digest: str
    canonical_authorization_bytes: bytes


@dataclass(frozen=True)
class OfflineChairAuthorizationVerifier:
    """Immutable I-domain service supplied solely by trusted bootstrap."""
    root: OfflineChairTrustRoot

    def __post_init__(self):
        if type(self.root) is not OfflineChairTrustRoot:
            raise OfflineChairAuthenticationError("sealed trusted setup root required")

    def verify(self, authorization, *, store_identity, campaign_id):
        if (type(authorization) is not Authorization or
                authorization.schema_version != AUTHORIZATION_V2_SCHEMA):
            raise OfflineChairAuthenticationError("historical v1 cannot authorize U-04")
        try:
            raw = canonical_authorization_bytes(authorization)
            digest = authorization_digest(authorization)
        except ContractError as exc:
            raise OfflineChairAuthenticationError("invalid authorization policy") from exc
        root = self.root
        if (authorization.authorization_digest != digest or
                authorization.campaign_id != campaign_id or
                authorization.trust_domain != root.trust_domain or
                authorization.chair_identity not in root.trusted_chair_ids):
            raise OfflineChairAuthenticationError("authorization target/digest/Chair mismatch")
        matches = [entry for entry in root.approvals if (
            entry.store_identity == store_identity and entry.campaign_id == campaign_id and
            entry.authorization_id == authorization.authorization_id and
            entry.authorization_schema == authorization.schema_version and
            entry.authorization_digest == digest and entry.canonical_authorization_bytes == raw and
            entry.chair_identity == authorization.chair_identity and
            entry.trust_domain == authorization.trust_domain)]
        if len(matches) != 1:
            raise OfflineChairAuthenticationError("complete exact authorization was not enrolled")
        return OfflineChairAuthenticationResult(root.root_id, root.root_version,
            store_identity, campaign_id, authorization.authorization_id, digest, raw)


@dataclass(frozen=True)
class OfflineBootActivationApproval:
    store_identity: str
    authorization_digest: str
    chair_identity: str
    activation_id: str
    boot_ordinal: int
    observed_boot_id: str

    def __post_init__(self):
        from .contracts import _string
        for name in ('store_identity', 'chair_identity', 'activation_id', 'observed_boot_id'):
            _string(name, getattr(self, name))
        _string('authorization_digest', self.authorization_digest, digest=True)
        if type(self.boot_ordinal) is not int or not 1 <= self.boot_ordinal <= 4:
            raise OfflineChairAuthenticationError('closed enrolled boot ordinal required')


@dataclass(frozen=True)
class OfflineBootActivationAuthentication:
    verifier_id: str
    canonical_bytes: bytes
    digest: str


@dataclass(frozen=True)
class OfflineBootActivationVerifier:
    """Pinned independent offline activation enrollment, supplied at bootstrap.

    The enrolled activation/observed-boot identity is immutable. The exact
    predecessor is checked against its independently witnessed closure and
    included in the complete-byte authentication result. Runtime cannot enroll.
    """
    verifier_id: str
    approvals: tuple

    def __post_init__(self):
        if (type(self.verifier_id) is not str or not self.verifier_id or
                type(self.approvals) is not tuple or
                any(type(a) is not OfflineBootActivationApproval for a in self.approvals)):
            raise OfflineChairAuthenticationError('sealed activation enrollment required')
        identities = [(a.store_identity, a.authorization_digest, a.activation_id) for a in self.approvals]
        if len(set(identities)) != len(identities):
            raise OfflineChairAuthenticationError('ambiguous activation enrollment')

    def verify(self, activation, *, store_identity, authorization, predecessor_digest):
        from .contracts import BootActivation
        if (type(activation) is not BootActivation or
                activation.authenticated is not True or activation.predecessor_closure_digest != predecessor_digest):
            raise OfflineChairAuthenticationError('exact activation predecessor required')
        approval = OfflineBootActivationApproval(store_identity, activation.authorization_digest,
            activation.chair_identity, activation.activation_id, activation.boot_ordinal,
            activation.observed_boot_id)
        if (approval not in self.approvals or activation.authorization_digest != authorization.authorization_digest or
                activation.chair_identity != authorization.chair_identity):
            raise OfflineChairAuthenticationError('activation was not independently enrolled')
        raw = (json.dumps(asdict(activation), sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
        return OfflineBootActivationAuthentication(self.verifier_id, raw, hashlib.sha256(raw).hexdigest())

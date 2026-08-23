"""External Evaluator: outside the council's context and control.

The evaluator holds the hidden checks. Its configuration is never placed into
any stage's inputs; its version and configuration digest are recorded in run
provenance so the evaluation treatment is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .security import deep_freeze, digest_json


EVALUATOR_VERSION = "dev-eval-v1"


@dataclass(frozen=True)
class EvaluationConfig:
    """Development evaluation rules. In real runs this wraps hidden tests."""

    required_markers: tuple[str, ...] = ("PROPOSED_FIX",)
    prohibited_markers: tuple[str, ...] = ("MODIFIED_HIDDEN_TESTS",)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize to immutable canonical forms: sequences become tuples and
        # metadata is deep-frozen so post-construction caller mutation cannot
        # change evaluation behavior or the configuration digest.
        object.__setattr__(self, "required_markers", tuple(self.required_markers))
        object.__setattr__(self, "prohibited_markers", tuple(self.prohibited_markers))
        object.__setattr__(self, "metadata", deep_freeze(dict(self.metadata)))

    @property
    def config_digest(self) -> str:
        return digest_json(
            {
                "required_markers": list(self.required_markers),
                "prohibited_markers": list(self.prohibited_markers),
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True)
class EvaluationOutcome:
    passed: bool
    reasons: tuple[str, ...]
    evaluated_at: str
    evaluator_version: str = EVALUATOR_VERSION
    config_digest: str | None = None

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "reasons": list(self.reasons),
            "evaluated_at": self.evaluated_at,
            "evaluator_version": self.evaluator_version,
            "config_digest": self.config_digest,
        }


class ExternalEvaluator:
    """Single source of evaluator truth: constructed once, injected into the runner."""

    def __init__(self, config: EvaluationConfig) -> None:
        self._config = config

    @property
    def version(self) -> str:
        return EVALUATOR_VERSION

    @property
    def config_digest(self) -> str:
        return self._config.config_digest

    def evaluate(self, final_candidate: str) -> EvaluationOutcome:
        reasons: list[str] = []
        for marker in self._config.required_markers:
            if marker not in final_candidate:
                reasons.append(f"missing required marker: {marker}")
        for marker in self._config.prohibited_markers:
            if marker in final_candidate:
                reasons.append(f"prohibited content present: {marker}")
        return EvaluationOutcome(
            passed=not reasons,
            reasons=tuple(reasons) or ("all hidden checks satisfied",),
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            evaluator_version=self.version,
            config_digest=self.config_digest,
        )

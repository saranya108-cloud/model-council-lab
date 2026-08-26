"""Shared test fixtures for the M1 development harness."""

import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from model_council import (  # noqa: E402
    AdapterIdentity,
    Condition,
    EvaluationConfig,
    ExperimentRunner,
    ExternalEvaluator,
    ResourceLimits,
    RunSpec,
    SubprocessAdapter,
    TaskSpec,
)

FAKE_IDENTITY = AdapterIdentity(
    provider="fake-provider",
    model_id="fake-dev-model",
    model_version="v1",
    adapter_name="fake",
    adapter_version="v0",
)
IDENTITY_KEY = FAKE_IDENTITY.key()

TASK = TaskSpec(
    task_id="dev-001",
    bug_report="parse_date() crashes on leap-day input",
    workspace_id="ws-dev-001",
    allowed_files=("dates.py",),
)


def make_task(task_id="dev-001", **kwargs):
    return TaskSpec(
        task_id=task_id,
        bug_report=kwargs.get("bug_report", "example defect"),
        workspace_id=kwargs.get("workspace_id", f"ws-{task_id}"),
        allowed_files=kwargs.get("allowed_files", ("a.py",)),
        metadata=kwargs.get("metadata", {"purpose": "test"}),
    )


def make_spec(run_id, condition="A", seed=7, **limit_kwargs):
    return RunSpec(
        run_id=run_id,
        task_id="dev-001",
        condition=Condition(condition),
        model_identifier=IDENTITY_KEY,
        prompt_version="prompts-dev-v0",
        resource_limits=ResourceLimits(**limit_kwargs) if limit_kwargs else ResourceLimits(),
        seed=seed,
    )


def make_runner(tmp_path_or_str, kind="fake", options=None, identity=None, monotonic=None):
    root = Path(tmp_path_or_str) / "runs"
    process = SubprocessAdapter(identity or FAKE_IDENTITY, kind=kind, options=options)
    evaluator = ExternalEvaluator(EvaluationConfig())
    return ExperimentRunner(process, evaluator, runs_root=root, monotonic=monotonic), root


def transient_failure_options(state_dir, fail_before_call_count=2, **extra):
    """Fake-adapter test state: fail the first N-1 subprocess invocations.

    The counter lives outside model-visible treatment. Seed, role instruction,
    stage inputs, and resource limits stay identical across attempts.
    """
    counter = Path(state_dir) / "fake-invocation-counter"
    options = {
        "fail_before_call_count": int(fail_before_call_count),
        "invocation_counter_path": str(counter),
    }
    options.update(extra)
    return options


class TempRoot:
    """Context manager supplying a temporary directory path."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        return self._tmp.name

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False

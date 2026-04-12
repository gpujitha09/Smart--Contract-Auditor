"""Basic smoke tests for environment grading behavior."""

from environment import SmartContractAuditorEnv
from models import AuditAction


def test_grade_finding_shape():
    env = SmartContractAuditorEnv()
    obs = env.reset(task_name="basic_audit", seed=42)

    action = AuditAction(
        vulnerability_type="reentrancy",
        location="withdraw",
        severity="critical",
        fix_suggestion="Add require checks and update state before external call to prevent reentrancy.",
    )

    next_obs = env.step(action)
    assert next_obs.reward is not None
    assert 0.0 <= next_obs.reward <= 1.0


def test_final_score_non_negative_with_penalty():
    env = SmartContractAuditorEnv()
    env.reset(task_name="basic_audit", seed=1)

    bad_action = AuditAction(
        vulnerability_type="tx_origin",
        location="main",
        severity="low",
        fix_suggestion="bad",
    )

    env.step(bad_action)
    end_obs = env.step(AuditAction(vulnerability_type="done"))

    assert end_obs.reward is not None
    assert end_obs.reward >= 0.0

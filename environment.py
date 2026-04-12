import random
import uuid
from typing import Set, List, Dict, Optional

from openenv.core.env_server import Environment
from models import AuditAction, AuditObservation, AuditState, VALID_VULNERABILITY_TYPES
from contracts import TASK_CONTRACTS, TASK_MAX_STEPS, TASK_NAMES


FIX_QUALITY_KEYWORDS = {
    "require",
    "check",
    "update",
    "safemath",
    "modifier",
    "revert",
}


class SmartContractAuditorEnv(Environment):
    """RL environment for smart-contract security auditing."""

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        self._state = AuditState()
        self._contract: Dict = {}
        self._vulnerabilities: List[Dict] = []
        self._matched_indices: Set[int] = set()
        self._findings: List[Dict] = []
        self._max_steps: int = 5
        self._scores: List[float] = []
        self._task_name: str = "basic_audit"

    # â”€â”€ reset â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def reset(self, seed=None, episode_id=None, **kwargs) -> AuditObservation:
        task_name = kwargs.get("task_name", "basic_audit")
        if task_name not in TASK_CONTRACTS:
            task_name = "basic_audit"

        self._task_name = task_name

        # Pick a random contract for this task
        if seed is not None:
            random.seed(seed)
        self._contract = random.choice(TASK_CONTRACTS[task_name])
        self._vulnerabilities = self._contract["vulnerabilities"]
        self._max_steps = TASK_MAX_STEPS[task_name]
        self._matched_indices = set()
        self._findings = []
        self._scores = []

        self._state = AuditState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            task_name=task_name,
            total_vulnerabilities=len(self._vulnerabilities),
            found_vulnerabilities=0,
            current_score=0.0,
        )

        num_vulns = len(self._vulnerabilities)
        return AuditObservation(
            done=False,
            reward=None,
            contract_code=self._contract["code"],
            contract_name=self._contract["name"],
            task_name=task_name,
            findings_so_far=[],
            remaining_steps=self._max_steps,
            total_vulnerabilities_hint=num_vulns,
            valid_vulnerability_types=[
                v for v in VALID_VULNERABILITY_TYPES if v != "done"
            ],
            message=(
                f"Audit the contract '{self._contract['name']}'. "
                f"It contains {num_vulns} known vulnerabilit{'y' if num_vulns == 1 else 'ies'}. "
                f"You have {self._max_steps} steps. Submit findings or 'done' to finish."
            ),
        )

    # â”€â”€ step â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def step(self, action: AuditAction, timeout_s=None, **kwargs) -> AuditObservation:
        self._state.step_count += 1
        remaining = self._max_steps - self._state.step_count

        # â”€â”€ Agent signals done â”€â”€
        if action.vulnerability_type.lower().strip() == "done":
            final_score = self._compute_final_score()
            self._scores.append(final_score)
            self._state.current_score = final_score
            return AuditObservation(
                done=True,
                reward=final_score,
                contract_code=self._contract["code"],
                contract_name=self._contract["name"],
                task_name=self._task_name,
                findings_so_far=self._findings,
                remaining_steps=0,
                total_vulnerabilities_hint=len(self._vulnerabilities),
                message=self._summary_message(final_score),
            )

        # â”€â”€ Grade the finding â”€â”€
        reward = self._grade_finding(action)
        self._scores.append(reward)
        self._state.current_score = self._compute_final_score()

        msg = self._step_feedback(action, reward)

        # â”€â”€ Max steps reached â”€â”€
        if remaining <= 0:
            final_score = self._compute_final_score()
            return AuditObservation(
                done=True,
                reward=final_score,
                contract_code=self._contract["code"],
                contract_name=self._contract["name"],
                task_name=self._task_name,
                findings_so_far=self._findings,
                remaining_steps=0,
                total_vulnerabilities_hint=len(self._vulnerabilities),
                message=self._summary_message(final_score),
            )

        return AuditObservation(
            done=False,
            reward=reward,
            contract_code=self._contract["code"],
            contract_name=self._contract["name"],
            task_name=self._task_name,
            findings_so_far=self._findings,
            remaining_steps=remaining,
            total_vulnerabilities_hint=len(self._vulnerabilities),
            message=msg,
        )

    # â”€â”€ state property â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @property
    def state(self) -> AuditState:
        return self._state

    # â”€â”€ grading logic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _grade_finding(self, action: AuditAction) -> float:
        """Score a single finding against unmatched ground-truth vulns."""
        best_score = 0.0
        best_idx = -1
        vuln_type = action.vulnerability_type.lower().strip()
        location = action.location.lower().strip()
        severity = action.severity.lower().strip()

        for i, vuln in enumerate(self._vulnerabilities):
            if i in self._matched_indices:
                continue
            score = 0.0
            if vuln_type == vuln["type"].lower():
                score += 0.4                           # type match
                if location == vuln["location"].lower():
                    score += 0.3                       # location match
                if severity == vuln["severity"].lower():
                    score += 0.1                       # severity match
                if self._has_quality_fix(action.fix_suggestion):
                    score += 0.2                       # reasonable fix
            if score > best_score:
                best_score = score
                best_idx = i

        finding = {
            "type": action.vulnerability_type,
            "location": action.location,
            "severity": action.severity,
            "score": best_score,
            "matched": best_score > 0,
        }
        self._findings.append(finding)

        if best_idx >= 0 and best_score > 0:
            self._matched_indices.add(best_idx)
            self._state.found_vulnerabilities = len(self._matched_indices)

        return round(best_score, 2)

    def _compute_final_score(self) -> float:
        """Normalized score with false-positive penalty."""
        if not self._vulnerabilities:
            return 0.0
        matched_scores = [f["score"] for f in self._findings if f.get("matched")]
        false_positive_count = sum(1 for f in self._findings if not f.get("matched"))
        penalty_score = false_positive_count * 0.05
        total = len(self._vulnerabilities)
        raw_score = min(sum(matched_scores) / total, 1.0)
        score = round(max(0.0, raw_score - penalty_score), 3)
        score = max(0.0, min(1.0, score))
        return score

    def _has_quality_fix(self, fix_suggestion: Optional[str]) -> bool:
        if not fix_suggestion:
            return False
        text = fix_suggestion.strip().lower()
        return len(text) > 20 and any(k in text for k in FIX_QUALITY_KEYWORDS)

    # â”€â”€ feedback messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _step_feedback(self, action: AuditAction, reward: float) -> str:
        if reward >= 0.9:
            return f"Excellent! '{action.vulnerability_type}' in '{action.location}' is correct with a great fix. Reward: {reward}"
        elif reward >= 0.6:
            return f"Good find! '{action.vulnerability_type}' in '{action.location}' partially correct. Reward: {reward}"
        elif reward > 0:
            return f"Partial match for '{action.vulnerability_type}'. Check your location/severity. Reward: {reward}"
        else:
            return f"'{action.vulnerability_type}' in '{action.location}' did not match any known vulnerability. Reward: 0.0"

    def _summary_message(self, score: float) -> str:
        total = len(self._vulnerabilities)
        found = len(self._matched_indices)
        return (
            f"Audit complete. Found {found}/{total} vulnerabilities. "
            f"Final score: {score:.3f}"
        )

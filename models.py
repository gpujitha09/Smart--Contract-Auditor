"""
Typed models for the Smart Contract Security Auditor environment.
Action, Observation, and State are Pydantic BaseModel subclasses from openenv.
"""

from typing import List, Dict, Optional
from pydantic import Field
from openenv.core.env_server import Action, Observation, State


VALID_VULNERABILITY_TYPES = [
    "reentrancy",
    "integer_overflow",
    "access_control",
    "unchecked_return",
    "tx_origin",
    "selfdestruct",
    "timestamp_dependence",
    "front_running",
    "delegatecall",
    "denial_of_service",
    "precision_loss",
    "flash_loan",
    "oracle_manipulation",
    "uninitialized_storage",
    "done",  # Special: signals end of audit
]


class AuditAction(Action):
    """An agent's finding or 'done' signal."""
    vulnerability_type: str          # One of VALID_VULNERABILITY_TYPES
    location: str = ""               # Function name where the vuln exists
    severity: str = ""               # critical / high / medium / low
    fix_suggestion: str = ""         # Recommended fix description


class AuditObservation(Observation):
    """What the agent sees after each step."""
    # done: bool  and  reward: Optional[float]  inherited from Observation
    contract_code: str = ""
    contract_name: str = ""
    task_name: str = ""
    findings_so_far: List[Dict] = Field(default_factory=list)
    remaining_steps: int = 0
    total_vulnerabilities_hint: int = 0
    valid_vulnerability_types: List[str] = Field(
        default_factory=lambda: [v for v in VALID_VULNERABILITY_TYPES if v != "done"]
    )
    message: str = ""


class AuditState(State):
    """Internal state (episode_id and step_count inherited)."""
    task_name: str = ""
    total_vulnerabilities: int = 0
    found_vulnerabilities: int = 0
    current_score: float = 0.0

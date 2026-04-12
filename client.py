

from openenv.core.env_client import EnvClient
from openenv.core.client_types import StepResult
from models import AuditAction, AuditObservation, AuditState


class SmartContractAuditorClient(
    EnvClient[AuditAction, AuditObservation, AuditState]
):
    def _step_payload(self, action: AuditAction) -> dict:
        return {
            "vulnerability_type": action.vulnerability_type,
            "location": action.location,
            "severity": action.severity,
            "fix_suggestion": action.fix_suggestion,
        }

    def _parse_result(self, payload: dict) -> StepResult:
        obs_data = payload.get("observation", {})
        return StepResult(
            observation=AuditObservation(
                done=payload.get("done", False),
                reward=payload.get("reward"),
                contract_code=obs_data.get("contract_code", ""),
                contract_name=obs_data.get("contract_name", ""),
                task_name=obs_data.get("task_name", ""),
                findings_so_far=obs_data.get("findings_so_far", []),
                remaining_steps=obs_data.get("remaining_steps", 0),
                total_vulnerabilities_hint=obs_data.get("total_vulnerabilities_hint", 0),
                valid_vulnerability_types=obs_data.get("valid_vulnerability_types", []),
                message=obs_data.get("message", ""),
            ),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> AuditState:
        return AuditState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            task_name=payload.get("task_name", ""),
            total_vulnerabilities=payload.get("total_vulnerabilities", 0),
            found_vulnerabilities=payload.get("found_vulnerabilities", 0),
            current_score=payload.get("current_score", 0.0),
        )

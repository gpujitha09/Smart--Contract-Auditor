from typing import List, Tuple, Optional
import numpy as np
from agent_learner import AuditorAgent
from models import AuditAction, AuditObservation
from inference import query_llm, parse_llm_response


class EnsembleAuditor:
    

    def __init__(self, rl_agent: Optional[AuditorAgent] = None, llm_enabled: bool = False):
        """
        Initialize ensemble auditor.
        
        Args:
            rl_agent: Pre-trained RL agent (creates new if None)
            llm_enabled: Whether to use LLM (requires HF token)
        """
        self.rl_agent = rl_agent or AuditorAgent()
        self.llm_enabled = llm_enabled
        self.ensemble_history: List[dict] = []

    def audit_with_ensemble(
        self,
        obs: AuditObservation,
        rl_weight: float = 0.6,
        llm_weight: float = 0.4,
        require_agreement: bool = False,
    ) -> Tuple[AuditAction, dict]:
        """
        Get audit prediction from ensemble of RL + LLM.
        
        Args:
            obs: Audit observation with contract code
            rl_weight: Weight for RL agent confidence (0-1)
            llm_weight: Weight for LLM agent confidence (0-1)
            require_agreement: If True, only report if RL and LLM agree
            
        Returns:
            (action, metadata) where metadata contains confidence scores
        """
        # Ensure weights sum to 1
        total_weight = rl_weight + llm_weight
        rl_weight /= total_weight
        llm_weight /= total_weight

        # === Get RL prediction ===
        rl_action, rl_confidence = self._get_rl_prediction(obs)
        
        # === Get LLM prediction ===
        llm_action = None
        llm_confidence = 0.0
        if self.llm_enabled and llm_weight > 0:
            llm_action, llm_confidence = self._get_llm_prediction(obs)

        # === Combine predictions ===
        final_action, metadata = self._combine_predictions(
            rl_action,
            rl_confidence,
            rl_weight,
            llm_action,
            llm_confidence,
            llm_weight,
            require_agreement=require_agreement,
        )

        # Store in history
        self.ensemble_history.append({
            "contract": obs.contract_name,
            "rl_prediction": rl_action.vulnerability_type,
            "rl_confidence": float(rl_confidence),
            "llm_prediction": llm_action.vulnerability_type if llm_action else "skipped",
            "llm_confidence": float(llm_confidence),
            "final_action": final_action.vulnerability_type,
            "agreement": rl_action.vulnerability_type == (
                llm_action.vulnerability_type if llm_action else rl_action.vulnerability_type
            ),
        })

        return final_action, metadata

    def _get_rl_prediction(self, obs: AuditObservation) -> Tuple[AuditAction, float]:
        """
        Get RL agent prediction with confidence score.
        
        Returns:
            (action, confidence_0_to_1)
        """
        action = self.rl_agent.audit(obs, training=False)
        
        # Estimate confidence from Q-value
        if hasattr(self.rl_agent, 'q_agent'):
            features = self.rl_agent.encoder.encode(obs.contract_code)
            state = self.rl_agent.q_agent.encode_state(features)
            
            # Get Q-values for valid actions
            valid_indices = [i for i, v in enumerate(
                self.rl_agent.vulnerability_names
            ) if v == action.vulnerability_type]
            
            if valid_indices:
                q_values = [self.rl_agent.q_agent.q_table[state, i] for i in valid_indices]
                max_q = max(q_values)
                # Normalize to 0-1 range (crude approximation)
                confidence = max(0.0, min(1.0, (max_q + 1.0) / 2.0))
            else:
                confidence = 0.5
        else:
            confidence = 0.5

        return action, confidence

    def _get_llm_prediction(self, obs: AuditObservation) -> Tuple[AuditAction, float]:
        """
        Get LLM prediction with confidence score.
        
        Returns:
            (action, confidence_0_to_1)
        """
        # Build prompt for LLM
        from inference import SYSTEM_PROMPT
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Contract: {obs.contract_name}\n"
            f"```solidity\n{obs.contract_code}\n```\n\n"
            f"Find a vulnerability:"
        )

        try:
            response = query_llm([
                {"role": "user", "content": prompt}
            ])
            action = parse_llm_response(response)
            
            # Confidence: higher if response contains well-formed JSON
            confidence = 0.7 if action.vulnerability_type != "done" else 0.3
            
            return action, confidence
            
        except Exception as e:
            # Fallback on LLM failure
            print(f"  [ENSEMBLE] LLM failed: {str(e)[:50]}")
            from models import VALID_VULNERABILITY_TYPES
            fallback_action = AuditAction(vulnerability_type="done")
            return fallback_action, 0.0

    def _combine_predictions(
        self,
        rl_action: AuditAction,
        rl_confidence: float,
        rl_weight: float,
        llm_action: Optional[AuditAction],
        llm_confidence: float,
        llm_weight: float,
        require_agreement: bool = False,
    ) -> Tuple[AuditAction, dict]:
        """
        Combine RL and LLM predictions using weighted voting.
        
        Returns:
            (final_action, metadata_dict)
        """
        metadata = {
            "rl_confidence": rl_confidence,
            "llm_confidence": llm_confidence,
            "rl_weight": rl_weight,
            "llm_weight": llm_weight,
            "agree": False,
        }

        # If LLM disabled, just return RL
        if not llm_action:
            return rl_action, metadata

        # Check agreement
        agree = rl_action.vulnerability_type == llm_action.vulnerability_type
        metadata["agree"] = agree

        if agree:
            # Both agree: use higher confidence version
            if rl_confidence >= llm_confidence:
                return rl_action, {**metadata, "strategy": "rl_agreed"}
            else:
                return llm_action, {**metadata, "strategy": "llm_agreed"}

        elif require_agreement:
            # Require agreement: return "done" (no finding) if disagree
            return AuditAction(vulnerability_type="done"), {
                **metadata,
                "strategy": "disagreement_cautious"
            }

        else:
            # Weighted voting: choose by weighted confidence
            rl_score = rl_confidence * rl_weight
            llm_score = llm_confidence * llm_weight

            if rl_score > llm_score:
                return rl_action, {**metadata, "strategy": "weighted_rl"}
            else:
                return llm_action, {**metadata, "strategy": "weighted_llm"}

    def get_ensemble_stats(self) -> dict:
        """Return statistics about ensemble predictions."""
        if not self.ensemble_history:
            return {}

        agreements = sum(1 for h in self.ensemble_history if h["agreement"])
        
        return {
            "total_predictions": len(self.ensemble_history),
            "rl_llm_agreement_rate": agreements / len(self.ensemble_history) if self.ensemble_history else 0,
            "avg_rl_confidence": float(np.mean([h["rl_confidence"] for h in self.ensemble_history])),
            "avg_llm_confidence": float(np.mean([h["llm_confidence"] for h in self.ensemble_history])) if any(h["llm_confidence"] > 0 for h in self.ensemble_history) else 0,
        }

"""
Q-Learning Agent for Smart Contract Auditing.

The agent learns to map contract features to optimal vulnerability findings.
State representation: encoded contract characteristics.
Action space: vulnerability types to report.
Reward: accuracy of findings.
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, Tuple, List, Optional
from datetime import datetime

from models import VALID_VULNERABILITY_TYPES, AuditAction, AuditObservation


class ContractStateEncoder:
    """Converts contract code into a numerical feature vector for RL agent."""

    FEATURES = [
        "has_call",        # Low-level call() usage
        "has_delegatecall",  # delegatecall usage (context switching)
        "has_selfdestruct",  # selfdestruct opcode
        "has_send",        # .send() method
        "has_transfer",    # .transfer() method
        "has_mapping",     # State storage with mapping
        "has_timestamp",   # block.timestamp dependency
        "has_blockhash",   # blockhash usage
        "has_tx_origin",   # tx.origin usage (not msg.sender)
        "has_loop",        # for/while loops (DoS risk)
        "has_assembly",    # Inline assembly (risky)
        "has_pragma_old",  # Old pragma version (< 0.8.0)
        "has_external",    # External functions
        "has_public",      # Public functions
        "has_fallback",    # Fallback/receive functions
        "contract_size",   # Normalized code size
    ]

    def __init__(self):
        self.n_features = len(self.FEATURES)

    def encode(self, contract_code: str) -> np.ndarray:
        """
        Extract 16 binary/normalized features from contract code.
        
        Returns:
            np.ndarray: Feature vector of shape (16,) with values 0-1
        """
        features = []

        # Convert to lowercase for pattern matching (reduce false negatives)
        code_lower = contract_code.lower()
        
        # Extract binary features based on pattern presence
        features.append(1 if ".call" in code_lower else 0)
        features.append(1 if "delegatecall" in code_lower else 0)
        features.append(1 if "selfdestruct" in code_lower else 0)
        features.append(1 if ".send(" in code_lower else 0)
        features.append(1 if ".transfer(" in code_lower else 0)
        features.append(1 if "mapping(" in code_lower else 0)
        features.append(1 if "block.timestamp" in code_lower else 0)
        features.append(1 if "blockhash" in code_lower else 0)
        features.append(1 if "tx.origin" in code_lower else 0)
        features.append(1 if "for (" in code_lower or "while (" in code_lower else 0)
        features.append(1 if "assembly" in code_lower else 0)
        features.append(1 if "^0.7" in code_lower or "^0.6" in code_lower else 0)
        features.append(1 if "external" in code_lower else 0)
        features.append(1 if "public" in code_lower else 0)
        features.append(1 if "fallback" in code_lower or "receive" in code_lower else 0)
        
        # Normalize contract size: 0-1 scale (capped at 1000 chars)
        contract_size = min(len(contract_code) / 1000.0, 1.0)
        features.append(contract_size)

        return np.array(features, dtype=np.float32)


class VulnerabilityPredictor:
    """Pattern-based heuristic to suggest vulnerabilities."""

    PATTERN_MAP = {
        "reentrancy": [".call", ".send", "mapping"],
        "integer_overflow": ["mapping", "+", "-", "*"],
        "access_control": ["require", "msg.sender"],
        "unchecked_return": [".send", ".call"],
        "tx_origin": ["tx.origin"],
        "selfdestruct": ["selfdestruct"],
        "timestamp_dependence": ["block.timestamp"],
        "front_running": ["external", "public"],
        "delegatecall": ["delegatecall"],
        "denial_of_service": ["for (", "while ("],
        "precision_loss": ["division", "/"],
        "flash_loan": ["transfer", "balance"],
        "oracle_manipulation": ["getPrice", "oracle"],
        "uninitialized_storage": ["storage", "initialization"],
    }

    @classmethod
    def predict_likely_vulnerabilities(cls, contract_code: str) -> List[Tuple[str, float]]:
        """
        Return list of (vulnerability_type, confidence) tuples.
        Confidence is 0.0 to 1.0 based on pattern matches.
        """
        predictions = []
        code_lower = contract_code.lower()

        for vuln_type, patterns in cls.PATTERN_MAP.items():
            matches = sum(1 for p in patterns if p.lower() in code_lower)
            confidence = min(matches / len(patterns), 1.0) if patterns else 0.0
            if confidence > 0.0:
                predictions.append((vuln_type, confidence))

        return sorted(predictions, key=lambda x: -x[1])


class QLearningAgent:
    """
    Standard Q-Learning agent for Markov Decision Process (MDP).
    
    Learns state-action value function Q(s,a) to maximize cumulative reward.
    State: discretized contract features (32 bins)
    Action: vulnerability type index
    Reward: accuracy of audit finding (0.0-1.0)
    """

    def __init__(self, n_vulnerability_types: int = len(VALID_VULNERABILITY_TYPES) - 1):
        # === State and Action Spaces ===
        self.n_states = 32  # Discretized feature space into 32 state bins
        self.n_actions = n_vulnerability_types  # One action per vulnerability type
        
        # === Q-Table: Core Learning Structure ===
        # Shape: (n_states, n_actions)
        # Stores learned value of each state-action pair
        self.q_table = np.zeros((self.n_states, self.n_actions), dtype=np.float32)
        
        # === Hyperparameters (tuned for vulnerability detection) ===
        self.alpha = 0.1      # Learning rate: 10% weight to new experience (conservative)
        self.gamma = 0.95     # Discount factor: future rewards matter (long-term thinking)
        self.epsilon = 0.1    # Exploration rate: 10% chance to explore randomly
        
        self.encoder = ContractStateEncoder()
        self.learning_history: List[Dict] = []

    def encode_state(self, features: np.ndarray) -> int:
        """
        Discretize continuous feature vector (16 dims) into state index (0-31).
        
        Strategy: Sum first 10 binary features and scale to [0, 32)
        This groups similar contract patterns into same state for learning.
        
        Args:
            features: np.ndarray of shape (16,) with values 0-1
            
        Returns:
            int: State index in [0, 31]
        """
        # Sum first 10 features (most discriminative), scale by 4, mod 32
        # Higher sum â†’ contract more likely to have vulnerabilities
        state_idx = int(np.sum(features[:10]) * 4) % self.n_states
        return state_idx

    def select_action(self, state: int, valid_actions: List[int], training: bool = False) -> int:
        """
        Epsilon-greedy action selection (exploration vs exploitation trade-off).
        
        During training:
          - With probability epsilon (10%): randomly explore
          - With probability 1-epsilon (90%): exploit best known action
          
        During inference: Always exploit best action
        
        Args:
            state: Current state index
            valid_actions: List of allowed action indices
            training: If True, use exploration; else exploit
            
        Returns:
            int: Selected action index
        """
        if training and np.random.random() < self.epsilon:
            # === EXPLORATION ===
            # Try random action to discover new patterns
            return np.random.choice(valid_actions)
        else:
            # === EXPLOITATION ===
            # Choose action with highest Q-value in this state
            scores = [self.q_table[state, a] for a in valid_actions]
            max_score = max(scores)
            best_actions = [a for a, s in zip(valid_actions, scores) if s == max_score]
            # Break ties randomly if multiple actions have same Q-value
            return np.random.choice(best_actions)

    def update(self, state: int, action: int, reward: float, next_state: int):
        """
        Q-Learning Bellman equation update.
        
        New Q-value = old Q-value + alpha * (reward + gamma * max Q(next_state) - old Q-value)
        
        Intuition: Update estimate of state-action pair based on:
          1. Immediate reward from action
          2. Discounted future value from next state
          
        Args:
            state: Current state
            action: Action taken
            reward: Reward received (0.0-1.0)
            next_state: State transitioned to
        """
        # Maximum possible future value from next state
        max_next_q = np.max(self.q_table[next_state, :])
        
        # Current Q-value estimate
        current_q = self.q_table[state, action]
        
        # Compute new Q-value using Bellman equation
        # Temporal difference (reward + gamma * max_next_q - current_q) drives learning
        new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        
        # Update Q-table in-place
        self.q_table[state, action] = new_q

    def save(self, filepath: str):
        """
        Persist Q-table and training metadata to JSON file.
        
        Useful for: 
        - Resuming training later
        - Deploying pre-trained agent
        - Analyzing learning curves
        
        Args:
            filepath: Path to save JSON file (creates parent dirs if needed)
        """
        data = {
            "q_table": self.q_table.tolist(),  # Convert numpy array to JSON-serializable list
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "learning_history": self.learning_history,
            "timestamp": datetime.now().isoformat(),
        }
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, filepath: str):
        """
        Load pre-trained Q-table from JSON file.
        
        Args:
            filepath: Path to JSON checkpoint (silently skips if not found)
        """
        if not Path(filepath).exists():
            return  # Silent fail: use untrained Q-table
        with open(filepath, "r") as f:
            data = json.load(f)
        self.q_table = np.array(data["q_table"], dtype=np.float32)
        self.alpha = data.get("alpha", 0.1)
        self.gamma = data.get("gamma", 0.95)
        self.epsilon = data.get("epsilon", 0.1)
        self.learning_history = data.get("learning_history", [])


class AuditorAgent:
    """High-level agent that combines Q-learning with pattern heuristics."""

    def __init__(self):
        self.q_agent = QLearningAgent()
        self.encoder = ContractStateEncoder()
        self.predictor = VulnerabilityPredictor()
        self.vulnerability_actions = [
            i for i, v in enumerate(VALID_VULNERABILITY_TYPES) if v != "done"
        ]
        self.vulnerability_names = [
            v for v in VALID_VULNERABILITY_TYPES if v != "done"
        ]

    def audit(
        self,
        obs: AuditObservation,
        training: bool = False,
    ) -> AuditAction:
        """
        Generate next audit finding or 'done' signal.
        
        Strategy:
        1. Use heuristic patterns to identify likely vulnerabilities
        2. Use Q-learning to select which one to report
        3. Generate sensible location/severity based on patterns
        """
        contract_code = obs.contract_code
        contract_name = obs.contract_name
        remaining_steps = obs.remaining_steps

        # Extract state features
        features = self.encoder.encode(contract_code)
        state = self.q_agent.encode_state(features)

        # If few steps left or confidence is low, consider finishing
        if remaining_steps <= 1:
            return AuditAction(vulnerability_type="done")

        # Get likely vulnerabilities from pattern analysis
        likely_vulns = self.predictor.predict_likely_vulnerabilities(contract_code)

        if not likely_vulns:
            return AuditAction(vulnerability_type="done")

        # Q-learning selects among likely vulnerabilities
        action_idx = self.q_agent.select_action(
            state, self.vulnerability_actions, training=training
        )
        vuln_type = self.vulnerability_names[action_idx]

        # Generate location (heuristic)
        location = self._infer_location(contract_code, vuln_type)

        # Generate severity (heuristic)
        severity = self._infer_severity(vuln_type, contract_code)

        # Generate fix suggestion
        fix = self._generate_fix_suggestion(vuln_type, location)

        return AuditAction(
            vulnerability_type=vuln_type,
            location=location,
            severity=severity,
            fix_suggestion=fix,
        )

    def _infer_location(self, contract_code: str, vuln_type: str) -> str:
        """Heuristically infer function name where vulnerability likely exists."""
        location_hints = {
            "reentrancy": "withdraw",
            "integer_overflow": "transfer",
            "access_control": "setOwner",
            "unchecked_return": "send",
            "tx_origin": "distribute",
            "selfdestruct": "destroy",
            "timestamp_dependence": "bid",
            "front_running": "execute",
            "delegatecall": "proxy",
            "denial_of_service": "loop",
            "precision_loss": "calculate",
            "flash_loan": "flash",
            "oracle_manipulation": "price",
            "uninitialized_storage": "storage",
        }
        
        hint = location_hints.get(vuln_type, "main")
        code_lower = contract_code.lower()
        
        # Try to find actual function with hints
        if hint.lower() in code_lower:
            return hint
        
        # Fallback to first function found
        functions = ["constructor", "receive", "fallback"]
        for fn in functions:
            if fn in code_lower:
                return fn
        return "main"

    def _infer_severity(self, vuln_type: str, contract_code: str) -> str:
        """Infer severity based on vulnerability type."""
        critical_vulns = {
            "reentrancy",
            "integer_overflow",
            "access_control",
            "selfdestruct",
        }
        
        high_vulns = {
            "unchecked_return",
            "tx_origin",
            "denial_of_service",
            "delegatecall",
        }
        
        if vuln_type in critical_vulns:
            return "critical"
        elif vuln_type in high_vulns:
            return "high"
        elif vuln_type in {"timestamp_dependence", "precision_loss"}:
            return "medium"
        else:
            return "low"

    def _generate_fix_suggestion(self, vuln_type: str, location: str) -> str:
        """Generate a reasonable fix suggestion."""
        suggestions = {
            "reentrancy": f"Update state before external call in {location}. Use checks-effects-interactions pattern.",
            "integer_overflow": "Use SafeMath library or upgrade to Solidity >=0.8.0 with built-in overflow checks.",
            "access_control": f"Add require(msg.sender == owner) check to {location} function.",
            "unchecked_return": f"Check return value of external call in {location} or use low-level call with require.",
            "tx_origin": "Replace tx.origin with msg.sender for authentication.",
            "selfdestruct": "Remove selfdestruct or wrap with proper access control.",
            "timestamp_dependence": "Use block.number instead of block.timestamp, or document and accept the risk.",
            "front_running": "Use commit-reveal scheme or randomness to prevent front-running.",
            "delegatecall": "Carefully validate all delegatecall targets. Ensure state variable layout matches.",
            "denial_of_service": "Replace push-based loops with pull-based withdrawal pattern.",
            "precision_loss": "Use fixed-point math or multiply before dividing.",
            "flash_loan": "Validate balance before and after external calls.",
            "oracle_manipulation": "Use multiple oracle sources or time-weighted average prices.",
            "uninitialized_storage": "Ensure all storage variables are properly initialized.",
        }
        return suggestions.get(vuln_type, f"Review {vuln_type} vulnerability in {location}.")

    def save(self, filepath: str):
        """Save agent state."""
        self.q_agent.save(filepath)

    def load(self, filepath: str):
        """Load agent state."""
        self.q_agent.load(filepath)

"""
Environment configuration for Smart Contract Auditor.
Manages API keys, models, and settings via environment variables.
"""

import os
from pathlib import Path


class Config:
    """Central configuration manager."""

    # API Keys - read from environment variables (required by Scaler submission)
    HF_TOKEN = os.getenv("HF_TOKEN", "")
    API_BASE_URL = os.getenv("API_BASE_URL", "https://api-inference.huggingface.co/v1")
    MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

    # Model settings
    TEMPERATURE = 0.3
    MAX_TOKENS = 500

    # Environment
    BENCHMARK_NAME = "smart_contract_auditor"
    SUCCESS_SCORE_THRESHOLD = 0.3

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    MODELS_DIR = PROJECT_ROOT / "models"
    LOGS_DIR = PROJECT_ROOT / "logs"
    DATA_DIR = PROJECT_ROOT / "data"

    # Model checkpoints
    RL_MODEL_PATH = MODELS_DIR / "auditor_agent.json"
    TRAINING_LOG_PATH = LOGS_DIR / "training_log.json"

    def __init__(self):
        """Ensure directories exist."""
        self.MODELS_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
        self.DATA_DIR.mkdir(exist_ok=True)

    @classmethod
    def get_hf_headers(cls):
        """Get HF API headers."""
        return {"Authorization": f"Bearer {cls.HF_TOKEN}"}


# Global instance
config = Config()

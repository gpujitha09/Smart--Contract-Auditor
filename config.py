import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # .env loading is optional if python-dotenv is not installed.
    pass


class Config:
    


    HF_TOKEN = os.getenv("HF_TOKEN", "")
    API_BASE_URL = os.getenv("API_BASE_URL", "https://api-inference.huggingface.co/v1")
    MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

   
    TEMPERATURE = 0.3
    MAX_TOKENS = 500

    
    BENCHMARK_NAME = "smart_contract_auditor"
    SUCCESS_SCORE_THRESHOLD = 0.6

    
    PROJECT_ROOT = Path(__file__).parent
    MODELS_DIR = PROJECT_ROOT / "models"
    LOGS_DIR = PROJECT_ROOT / "logs"
    DATA_DIR = PROJECT_ROOT / "data"

    
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



config = Config()

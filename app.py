"""FastAPI server — one line of meaningful code."""

from openenv.core.env_server import create_fastapi_app
from .environment import SmartContractAuditorEnv
from .models import AuditAction, AuditObservation

app = create_fastapi_app(SmartContractAuditorEnv, AuditAction, AuditObservation)

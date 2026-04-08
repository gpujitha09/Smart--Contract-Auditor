"""FastAPI server â€” one line of meaningful code."""

from openenv.core.env_server import create_fastapi_app
from environment import SmartContractAuditorEnv
from models import AuditAction, AuditObservation

app = create_fastapi_app(SmartContractAuditorEnv, AuditAction, AuditObservation)

def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()

"""FastAPI server — one line of meaningful code."""

from openenv.core.env_server import create_fastapi_app
from environment import SmartContractAuditorEnv
from models import AuditAction, AuditObservation
import gradio as gr
from dashboard import demo

app = create_fastapi_app(SmartContractAuditorEnv, AuditAction, AuditObservation)
app = gr.mount_gradio_app(app, demo, path="/")

def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()

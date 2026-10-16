"""
Root entrypoint (`app.py`) for Free Tier Python PaaS & Hugging Face Spaces (Gradio/Python SDK).
Launches the FalkorTrace FastAPI + MCP server on $PORT / $GRADIO_SERVER_PORT (default 7860).
"""

import os
import uvicorn
from backend.main import app

if __name__ == "__main__":
    port = int(os.getenv("PORT", os.getenv("GRADIO_SERVER_PORT", "7860")))
    uvicorn.run(app, host="0.0.0.0", port=port)

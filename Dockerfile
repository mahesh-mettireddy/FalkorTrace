FROM falkordb/falkordb:latest

# Install Python 3 & pip inside the official FalkorDB GraphBLAS container
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create isolated virtualenv so pip install works cleanly on Debian/Ubuntu PEP-668
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY docs/ ./docs/
COPY README.md ./
COPY start.sh ./

# Normalize Windows CRLF line endings if present and make executable
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh && chmod -R 777 /app

# Default to port 7860 for Hugging Face Spaces (overridable via $PORT on Render/Railway/Docker)
ENV PORT=7860
EXPOSE 7860 8000 6379

CMD ["/app/start.sh"]

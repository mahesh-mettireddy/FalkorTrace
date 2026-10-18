FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY api/ ./api/
COPY tests/ ./tests/
COPY docs/ ./docs/
COPY README.md ./
COPY Walkthrough.md ./

RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

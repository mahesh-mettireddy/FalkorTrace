#!/usr/bin/env bash
set -e

# 1. If FALKORDB_HOST is localhost (default in single-container PaaS like Hugging Face Spaces / Render),
#    launch the embedded FalkorDB Redis module in the background if available.
if [ "${FALKORDB_HOST:-localhost}" = "localhost" ] || [ "${FALKORDB_HOST}" = "127.0.0.1" ]; then
  if command -v redis-server >/dev/null 2>&1 && [ -f "/var/lib/falkordb/bin/falkordb.so" ]; then
    echo "[FalkorTrace] Starting local FalkorDB GraphBLAS engine on port ${FALKORDB_PORT:-6379}..."
    redis-server --loadmodule /var/lib/falkordb/bin/falkordb.so --port "${FALKORDB_PORT:-6379}" --daemonize yes
    sleep 1
  fi
fi

# 2. Start the FastAPI + MCP Server on $PORT (defaults to 7860 for Hugging Face Spaces, or 8000 locally)
APP_PORT="${PORT:-7860}"
echo "[FalkorTrace] Launching FastAPI & MCP Triage Server on 0.0.0.0:${APP_PORT}..."
exec uvicorn backend.main:app --host 0.0.0.0 --port "${APP_PORT}"

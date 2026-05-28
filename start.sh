#!/usr/bin/env bash
# ============================================================
# PILA Suite — Home Server Startup Script (venv-aware)
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PILA_PORT:-8000}"
HOST="${PILA_HOST:-0.0.0.0}"
LOG="$SCRIPT_DIR/pila.log"
VENV="$SCRIPT_DIR/venv"

echo "================================================"
echo "  PILA SUITE v1.0.0"
echo "  PSIL  |  IRV  |  LMEP  |  AESP"
echo "================================================"
echo ""

# Activate the venv (the one and only Python environment we use)
if [ ! -d "$VENV" ]; then
    echo "ERROR: venv not found at $VENV"
    echo "Create it with:  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi
# shellcheck source=/dev/null
source "$VENV/bin/activate"
PY="$VENV/bin/python"
echo "→ Using venv:  $VENV"

# Sanity check: ensure base deps are present in the venv
echo "→ Checking dependencies..."
"$PY" -c "import fastapi, uvicorn, elasticsearch" 2>/dev/null || {
    echo "→ Installing dependencies into venv from requirements.txt..."
    "$PY" -m pip install -r requirements.txt -q
}

# Kill any existing instance on the port
existing=$(lsof -ti:$PORT 2>/dev/null || true)
if [ -n "$existing" ]; then
    echo "→ Stopping existing process on port $PORT..."
    kill $existing 2>/dev/null || true
    sleep 1
fi

echo "→ Starting PILA Suite on $HOST:$PORT ..."
export PYTHONPATH="$SCRIPT_DIR"
cd "$SCRIPT_DIR"

# Choose professional vs community server
if [ -f "$SCRIPT_DIR/api/server.py" ]; then
    SERVER="api.server:app"
else
    SERVER="api.server_community:app"
    echo "→ Running Community Edition (no Professional server found)"
fi

if [ "$1" == "--foreground" ] || [ "$1" == "-f" ]; then
    "$PY" -m uvicorn $SERVER --host "$HOST" --port "$PORT" --log-level info
else
    nohup "$PY" -m uvicorn $SERVER \
        --host "$HOST" \
        --port "$PORT" \
        --log-level info \
        > "$LOG" 2>&1 &
    PID=$!
    echo "$PID" > "$SCRIPT_DIR/pila.pid"
    sleep 2

    if kill -0 $PID 2>/dev/null; then
        echo ""
        echo "✓ PILA Suite is running (PID: $PID)"
        echo ""
        echo "  Dashboard:  http://localhost:$PORT/"
        echo "  API Docs:   http://localhost:$PORT/docs"
        echo "  Health:     http://localhost:$PORT/health"
        echo ""
        echo "  Log file:   $LOG"
        echo "  PID file:   $SCRIPT_DIR/pila.pid"
        echo ""
        echo "  To stop:    ./stop.sh"
        echo "  To follow:  tail -f $LOG"
    else
        echo "✗ Server failed to start. Check $LOG for details."
        exit 1
    fi
fi

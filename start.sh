#!/usr/bin/env bash
# ============================================================
# PILA Suite — Home Server Startup Script
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PILA_PORT:-8000}"
HOST="${PILA_HOST:-0.0.0.0}"
LOG="$SCRIPT_DIR/pila.log"

echo "================================================"
echo "  PILA SUITE v1.0.0"
echo "  PSIL  |  IRV  |  LMEP  |  AESP"
echo "================================================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.11+ first."
    exit 1
fi

# Install deps if needed
echo "→ Checking dependencies..."
python3 -c "import fastapi, uvicorn" 2>/dev/null || {
    echo "→ Installing dependencies..."
    pip3 install fastapi uvicorn pyyaml --break-system-packages -q
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

if [ "$1" == "--foreground" ] || [ "$1" == "-f" ]; then
    python3 api/server.py
else
    # Use community server if professional server not present
if [ -f "$SCRIPT_DIR/api/server.py" ]; then
    SERVER="api.server:app"
else
    SERVER="api.server_community:app"
    echo "→ Running Community Edition (no Professional server found)"
fi
nohup python3 -m uvicorn $SERVER \
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

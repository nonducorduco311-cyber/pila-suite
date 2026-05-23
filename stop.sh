#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/pila.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        rm "$PID_FILE"
        echo "✓ PILA Suite stopped (PID $PID)"
    else
        echo "Process $PID not running. Cleaning up PID file."
        rm "$PID_FILE"
    fi
else
    # Try to find by port
    PID=$(lsof -ti:8000 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill $PID && echo "✓ Stopped process on port 8000 (PID $PID)"
    else
        echo "PILA Suite does not appear to be running."
    fi
fi

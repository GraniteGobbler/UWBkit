#!/usr/bin/env bash
set -euo pipefail

PORT="/dev/ttyUSB0"
BAUD="115200"
HOST="127.0.0.1"
UDP_PORT="17754"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON_EXE="$SCRIPT_DIR/.venv/bin/python"
elif [[ -x "$SCRIPT_DIR/venv/bin/python" ]]; then
  PYTHON_EXE="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON_EXE="python3"
fi

echo "Using Python: $PYTHON_EXE"
"$PYTHON_EXE" "$SCRIPT_DIR/serial_to_zep_udp.py" --port "$PORT" --baud "$BAUD" --host "$HOST" --udp-port "$UDP_PORT" --verbose --log-wait

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "Creating virtual environment in $VENV_DIR"
python3 -m venv "$VENV_DIR"

echo "Upgrading pip"
"$VENV_DIR/bin/python" -m pip install --upgrade pip

echo "Installing requirements"
"$VENV_DIR/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo
echo "Done. Use run_serial_to_zep_udp.sh to start the bridge."

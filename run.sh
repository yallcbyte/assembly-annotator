#!/usr/bin/env bash
# Create the virtualenv if it is missing, then serve the app.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r requirements.txt
fi

PORT="${PORT:-5000}"
echo "Assembly Annotator -> http://127.0.0.1:${PORT}"
PORT="$PORT" exec .venv/bin/python app.py

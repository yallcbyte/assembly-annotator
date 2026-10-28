#!/usr/bin/env bash
# Create the virtualenv if needed, bring dependencies up to date, serve the app.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
fi
# Runs every time so a `git pull` that adds a dependency just works.
.venv/bin/pip install --quiet -r requirements.txt

PORT="${PORT:-5000}"
echo "Assembly Annotator -> http://127.0.0.1:${PORT}"
PORT="$PORT" exec .venv/bin/python app.py

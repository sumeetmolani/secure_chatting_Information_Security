#!/usr/bin/env bash
# setup.sh — One-shot setup and launch for SecureChat
# Usage: bash setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║          SecureChat — Setup Script                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Python check ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "❌  Python 3 not found. Please install Python 3.10+."
  exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓  Python $PY_VER detected"

# ── Virtual environment ────────────────────────────────────────────────────────
if [ ! -d "venv" ]; then
  echo "→  Creating virtual environment…"
  python3 -m venv venv
fi

source venv/bin/activate
echo "✓  Virtual environment activated"

# ── Install dependencies ───────────────────────────────────────────────────────
echo "→  Installing Python packages…"
pip install -q --upgrade pip
pip install -q -r backend/requirements.txt
echo "✓  Dependencies installed"

# ── Logs directory ─────────────────────────────────────────────────────────────
mkdir -p logs
echo "✓  Logs directory ready"

# ── Launch ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Starting SecureChat on http://localhost:5000        ║"
echo "║  Press Ctrl+C to stop                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

cd backend
python app.py

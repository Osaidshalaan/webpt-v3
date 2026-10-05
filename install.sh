#!/usr/bin/env bash
set -euo pipefail

if [ ! -f requirements.txt ]; then
    echo "requirements.txt not found. Run this from the repo root." >&2
    exit 1
fi

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

. .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo
echo "Environment ready."
echo "Run: python webpt_v2.py https://target.example -c 8"
echo "Or : python webpt_v2_test.py   (10/10 expected)"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

set -a
. ./.env
set +a

export PYTHONDONTWRITEBYTECODE=1
PYTHON="${TRINETRA_PYTHON:-/home/patil/depression-ai/bin/python}"

exec "$PYTHON" main.py "$@"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

set -a
. ./.env
set +a

export PYTHONDONTWRITEBYTECODE=1
PYTHON="${TRINETRA_PYTHON:-/home/patil/depression-ai/bin/python}"
IMAGE="${SANDBOX_WORKER_IMAGE:-trinetra-sandbox-worker:latest}"

unset TRINETRA_LLM_API_KEY TRINETRA_LLM_BASE_URL TRINETRA_LLM_MODEL

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'Worker image %s is missing. Build it first:\n\n' "$IMAGE" >&2
  printf '  sudo sandbox/docker/build.sh %s\n\n' "$IMAGE" >&2
  exit 1
fi

exec sudo -E "$PYTHON" -m uvicorn sandbox.manager:app --host 127.0.0.1 --port 8765 --workers 1

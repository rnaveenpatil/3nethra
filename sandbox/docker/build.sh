#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-trinetra-sandbox-worker:latest}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker build \
  --pull \
  --file "${ROOT}/sandbox/docker/Dockerfile.worker" \
  --tag "${IMAGE}" \
  "${ROOT}/sandbox"

echo "built ${IMAGE}"

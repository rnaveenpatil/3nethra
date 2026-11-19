#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

set -a
. ./.env
set +a

export PYTHONDONTWRITEBYTECODE=1
PYTHON="${TRINETRA_PYTHON:-/home/patil/depression-ai/bin/python}"
AUTO_START="${TRINETRA_TUI_AUTO_START:-true}"

case "${AUTO_START,,}" in
  1|true|yes|on)
    if [ "$(id -u)" -ne 0 ] && ! sudo -n true >/dev/null 2>&1; then
      printf 'Authorize sandbox startup (sudo password):\n'
      sudo -v || true
      printf '\n'
    fi
    ;;
esac

if ! "$PYTHON" -c 'import textual' >/dev/null 2>&1; then
  printf 'Textual is not installed for %s\n\n' "$PYTHON" >&2
  printf '  %s -m pip install "textual>=8,<9"\n\n' "$PYTHON" >&2
  exit 1
fi

exec "$PYTHON" -m ui.app

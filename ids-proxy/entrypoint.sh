#!/bin/sh
set -eu

EVENTS_PATH="${IDS_PROXY_EVENTS:-/app/data/events.json}"
LOG_PATH="${IDS_PROXY_LOG:-/app/logs/ids-proxy.log}"

mkdir -p "$(dirname "$EVENTS_PATH")"
if [ ! -f "$EVENTS_PATH" ]; then
  echo "[]" > "$EVENTS_PATH" || true
fi

mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH" || true

PORT="${PORT:-8000}"
WORKERS="${GUNICORN_WORKERS:-2}"
TIMEOUT="${GUNICORN_TIMEOUT:-60}"
WORKER_CLASS="${GUNICORN_WORKER_CLASS:-gevent}"

exec gunicorn --bind "0.0.0.0:${PORT}" --workers "$WORKERS" --worker-class "$WORKER_CLASS" --timeout "$TIMEOUT" proxy:app

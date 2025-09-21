#!/bin/sh
set -eu

MODE="${ATTACK_SIM_MODE:-cli}"

if [ "$MODE" = "server" ]; then
  PORT="${PORT:-9000}"
  WORKERS="${GUNICORN_WORKERS:-2}"
  TIMEOUT="${GUNICORN_TIMEOUT:-120}"
  exec gunicorn --bind "0.0.0.0:${PORT}" --workers "$WORKERS" --timeout "$TIMEOUT" server:app
fi

SCRIPT="/app/run_attacks.py"
args="$@"

has_target=0
for a in $args; do
  case "$a" in
    --target) has_target=1; break;;
    --target=*) has_target=1; break;;
  esac
done

if [ "$has_target" -eq 0 ]; then
  args="--target http://demo-app:5000 $args"
fi

/app/wait-for.sh "http://demo-app:5000" 60 || {
  echo "demo-app did not become healthy; aborting attack run"
  exit 10
}

exec python "$SCRIPT" $args

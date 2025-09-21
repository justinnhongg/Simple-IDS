#!/bin/sh
URL="$1"
MAX="${2:-60}"
SLEEP=1
COUNT=0

if [ -z "$URL" ]; then
  echo "wait-for.sh: no URL provided"
  exit 2
fi

echo "Waiting for $URL up to ${MAX}s..."
while [ $COUNT -lt "$MAX" ]; do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 2 "$URL" >/dev/null 2>&1; then
      echo "Service $URL is available"
      exit 0
    fi
  else
    if command -v wget >/dev/null 2>&1; then
      if wget -q -T 2 -O /dev/null "$URL"; then
        echo "Service $URL is available"
        exit 0
      fi
    else
      echo "Neither curl nor wget available in container; cannot perform health check"
      exit 3
    fi
  fi
  COUNT=$((COUNT + SLEEP))
  sleep $SLEEP
done

echo "Timeout waiting for $URL"
exit 4

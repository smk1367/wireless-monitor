#!/bin/sh
set -e
mkdir -p /app/data /app/logs
python3 -c 'from database import init_db; init_db()'
crontab /app/crontab
service cron start >/dev/null 2>&1 || true
if [ "${RUN_INITIAL_SCAN:-0}" = "1" ]; then python3 /app/scanner.py >> /app/logs/initial_scan.log 2>&1 & fi
exec python3 /app/api_server.py

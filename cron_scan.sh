#!/bin/sh
cd /app
python3 /app/scanner.py >> /app/logs/scan.log 2>&1

FROM wireless_monitor_mimosa-wireless-monitor:latest

WORKDIR /app

COPY . .

RUN chmod +x entrypoint.sh cron_scan.sh \
    && mkdir -p /app/data /app/logs

CMD ["/app/entrypoint.sh"]

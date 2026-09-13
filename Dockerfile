FROM wireless_monitor_mimosa-wireless-monitor:latest

WORKDIR /app

COPY . .

#RUN pip install --no-cache-dir -r requirements.txt \
#    && chmod +x entrypoint.sh cron_scan.sh \
#    && mkdir -p /app/data /app/logs
RUN pip install --no-cache-dir \
    --index-url https://mirror2.chabokan.net/pypi/simple/ \
    -r requirements.txt \
    && chmod +x entrypoint.sh cron_scan.sh \
    && mkdir -p /app/data /app/logs
CMD ["/app/entrypoint.sh"]

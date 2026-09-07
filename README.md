# Wireless Monitor – Extended

Features:
- Network discovery for 172.17.240.0/20 (configurable)
- MikroTik, Cisco, Racom collectors
- Multiple SSH credentials
- Legacy RouterOS SSH best-effort compatibility
- Blacklist by IP or CIDR (not scanned and hidden)
- Manual IP inventory and manual scan
- View / Full roles
- Historical scan results
- Device details organized in 8 dashboard tabs
- Docker Compose deployment

## Install
```bash
cp .env.example .env
vi .env
docker compose up -d --build
docker logs -f wireless-monitor
```
Open `http://SERVER_IP:5000`.

First admin is taken from DASHBOARD_USER/DASHBOARD_PASS.

## Important
The collector uses command families that differ by RouterOS/model. A field is shown only when the target device exposes/permits that information. Unsupported commands do not abort the whole scan.

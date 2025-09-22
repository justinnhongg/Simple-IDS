# Simple IDS Hackathon Demo

This repository contains a lightweight intrusion detection system that is easy to run on a laptop during a hackathon demo. It is organised as four small services:

- **demo-app** – a vulnerable web application that logs incoming activity.
- **attack-sim** – scripts that simulate brute force, SQL injection and port scanning attacks.
- **ids-proxy** – a detection service that receives telemetry from the demo app and turns it into human readable alerts.
- **dashboard** – a friendly UI that periodically polls the proxy and shows detections in plain English.

## Quick start

You only need Docker Desktop (or Docker Engine + Compose v2) installed locally. The repository exposes common workflows through `make` targets so you can get from zero to demo in one command.

### Demo in 30 seconds

1. `cp .env.example .env`
2. `make all`
3. Open <http://localhost:3000>, flip to **Health** for a metrics snapshot, then use the **Run Attack Scenarios** panel to replay the story live.

```bash
# Build images, start the stack, wait for health checks, run the simulator, and show fresh detections
make all

# ...or just build and start the services without firing the attacks
make up

# Follow the logs from ids-proxy and demo-app
make logs

# Re-run the attack simulator later on (CLI fallback)
make attack ARGS='--all --pace 1.5'

# Trigger via API with custom pace & scenarios (overrides ATTACK_SCENARIOS/ATTACK_PACE)
make attack ATTACK_SCENARIOS="sql portscan" ATTACK_PACE=1.2

# Tear everything down and reclaim volumes
make down

# Remove containers, volume, local logs
make clean
```

Open the dashboard at http://localhost:3000 and watch alerts stream in as the simulator runs. Health checks ensure the proxy, demo app, and dashboard are responding before attacks begin.

Prefer raw Compose commands? The same flows work with `docker compose up -d --build`, `docker compose run --rm attack-sim --all`, and `docker compose down -v`.

### Running services without Docker

Running everything directly on the host is still possible if you have Python 3.11+ available. In four separate terminals run:

```bash
cd demo-app    && pip install -r requirements.txt && python app.py
cd ids-proxy   && pip install -r requirements.txt && python proxy.py
cd dashboard   && pip install -r requirements.txt && python server.py
cd attack-sim  && pip install -r requirements.txt && python run_attacks.py --all
```

The services use the same ports as the containerised setup (demo-app forwards events to the proxy on port 8000; the dashboard listens on port 3000).

## How it works

1. The demo application exposes `/login`, `/search` and `/probe/<port>` endpoints and forwards a JSON log record to the IDS proxy for every request.
2. The IDS proxy analyses events:
   - five failed logins within one minute trigger a **brute force** alert,
   - a suspicious search query containing common SQL injection signatures triggers a **SQL injection** alert,
   - probing ten different ports within one minute triggers a **port scan** alert.
3. Detections are saved to `ids-proxy/data/events.json`, appended to `ids-proxy.log`, and exposed via `/events`.
4. The dashboard polls `/api/events` every few seconds and renders the incidents in a collapsible list.

All components are intentionally simple – the goal is to communicate the detection story in layman's terms, not to build a production grade system. Login attempts only include usernames and success/failure flags so passwords never hit disk.

### Alert UX upgrades

- Each alert ships with a plain-English explanation plus a copyable remediation snippet.
- Actions include `Mute IP 5m`, `Copy fix`, and `Export JSON` so non-security devs can react quickly.
- Optional Slack webhook support mirrors alerts into team channels; configure `SLACK_WEBHOOK_URL` and `DASHBOARD_URL`.
- Event persistence now uses atomic writes to keep `events.json` intact even under concurrent detections.

### Live controls & streaming

- `ids-proxy` pushes detections over Server-Sent Events (`/events/stream`), so the dashboard updates in real time without polling.
- The dashboard proxies the stream (`/api/events/stream`) and exposes a one-click launcher for individual scenarios via the attack-sim API.
- Attack metrics (/metrics) flow into inline sparklines on the dashboard **Health** page, keeping the “state of the war-room” visible to judges.

### Metrics & health endpoints

- `ids-proxy` exposes `/health` plus `/metrics` (JSON counters for brute force / SQLi / port scans).
- `dashboard` exposes `/health`, a judge-friendly HTML summary wired to the proxy metrics endpoint.

## Customisation

Environment variables let you change behaviour without editing code:

- `IDS_PROXY_INGEST` (demo-app) – URL for forwarding logs, defaults to `http://localhost:8000/ingest`.
- `DEMO_APP_LOG` – path to the application log file.
- `IDS_PROXY_LOG` / `IDS_PROXY_EVENTS` – where detections are stored.
- `IDS_PROXY_EVENTS_URL` (dashboard) – URL used to fetch detections, defaults to `http://localhost:8000/events`.
- `DASHBOARD_REFRESH` – refresh interval in seconds (dashboard).
- `IDS_PROXY_SQLI_PATTERNS_EXTRA` – comma-separated SQL injection patterns appended to the built-in signatures.
- `IDS_PROXY_LOG_MAX_BYTES` / `IDS_PROXY_LOG_BACKUPS` – rotate the proxy log once it exceeds the configured size (defaults to 5 MB and one backup).
- `IDS_PROXY_RETRIES`, `IDS_PROXY_RETRY_BACKOFF`, `IDS_PROXY_RETRY_JITTER` – tune how the demo app retries when the proxy is briefly unavailable.
- `IDS_PROXY_METRICS_URL` – where the dashboard fetches IDS metrics for the `/health` page.
- `IDS_PROXY_EVENTS_STREAM_URL` – SSE endpoint that feeds the dashboard’s live incident list.
- `ATTACK_SIM_ARGS` – defaults to `--all --pace 1.0`; override to slow down or speed up the CLI narrator.
- `ATTACK_SIM_URL` – dashboard backend base URL for the attack simulator API (`http://attack-sim:9000`).
- `ATTACK_SCENARIOS`, `ATTACK_PACE`, `ATTACK_TARGET` – optional overrides for `make attack` when using the API path.
- `ATTACK_SIM_TARGET` – default base URL the attack simulator uses when replaying scenarios (`http://demo-app:5000`).
- `ATTACK_ENDPOINT` – host-side URL used by `make attack` when calling the simulator API (`http://localhost:9000/run`).
- `ATTACK_SIM_TARGET_HEALTH` – path the simulator pings before launching scenarios (`/` by default).
- `ATTACK_SIM_SOURCE_IPS` – comma-separated list of spoofed IPs used to simulate multiple attackers (first IP drives the threshold breach).
- `ATTACK_SIM_BRUTEFORCE_ROUNDS`, `ATTACK_SIM_SQLI_ROUNDS`, `ATTACK_SIM_PORTSCAN_ROUNDS` – how many times each scenario loops through its payloads; bump these to flood the proxy during `make up`.

## Repository layout

```
attack-sim/      # CLI that triggers the attack scenarios (supports --pace for slower/faster demos)
dashboard/       # Flask app serving the web UI
demo-app/        # Flask demo web application
ids-proxy/       # Flask service performing the detection logic
```

## Troubleshooting

- **Containers stay "unhealthy"** – ensure Docker Desktop is running, then `make down && make up`.
- **Ports already in use** – adjust the published ports in `docker-compose.yml` (e.g., change `8000:8000`) before running `make up`.
- **Attack simulator races ahead** – export `ATTACK_SIM_ARGS='--all --pace 1.5'` or edit `.env` to slow the flow.
- **Attack simulator shows “busy”** – wait for the current run to finish; the dashboard health page mirrors the run queue.
- **No detections showing up** – visit `/health` on the dashboard to confirm connectivity and inspect logs with `make logs SERVICES=ids-proxy`.


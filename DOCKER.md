# Running the Simple-IDS demo with Docker Compose

This repo includes Dockerfiles and a `docker-compose.yml` to run the demo stack (ids-proxy, demo-app, dashboard). The attack simulator runs as a one-shot container. The easiest path is to use the bundled `Makefile` targets:

```bash
make up     # build + start ids-proxy, demo-app, dashboard
make all    # build + start + wait for health checks + run attack-sim
make attack # re-run attack simulator later (e.g. ARGS='--all --pace 1.5')
make down   # stop services and remove volumes
make clean  # prune containers, volume, and local logs
```

These targets call `docker compose` under the hood and ensure services are healthy before the simulator fires. If you need the raw Compose commands instead, the equivalents are:

```bash
docker compose build --pull
docker compose up -d ids-proxy demo-app dashboard
docker compose run --rm attack-sim --all
docker compose down -v
```

Open the dashboard at http://localhost:3000 when the stack is up.

Notes:
- The `ids-proxy` service mounts `ids-proxy/data` to persist detections across container restarts.
- `attack-sim` now runs as an always-on microservice (port 9000) so the dashboard can trigger scenarios on demand; the CLI fallback still works via `make attack ARGS=...`.
- `make all` waits for proxy, demo-app, dashboard, and attack-sim health endpoints before firing scenarios.
- Environment defaults live in `.env.example`; copy it to `.env` to override values without touching the compose file.

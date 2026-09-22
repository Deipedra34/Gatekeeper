# Grafana dashboard

[`gatekeeper-dashboard.json`](gatekeeper-dashboard.json) is a ready-to-import Grafana dashboard for the Prometheus metrics Gatekeeper exposes at `/metrics`.

<!-- TODO: Add a screenshot of the imported dashboard here. -->
![Grafana dashboard](../docs/images/grafana-dashboard.png)

> **Screenshot placeholder:** add a screenshot of the imported dashboard at `docs/images/grafana-dashboard.png`.

## What's on it

| Row | Panels | Metrics |
|---|---|---|
| Overview | Allowed rate, rejected rate, rejection ratio, cache hit ratio, p95 latency | all of the below |
| Rate limiting | Allowed vs rejected by tier, allowed vs rejected by client, quota remaining over time, quota remaining now | `gatekeeper_requests_allowed_total`, `gatekeeper_requests_rejected_total`, `gatekeeper_limiter_remaining` |
| Latency | p50/p95/p99, latency histogram (heatmap), p95 by route and status | `gatekeeper_request_duration_seconds` |
| Response cache | Hit ratio by route, hits vs misses | `gatekeeper_cache_hits_total`, `gatekeeper_cache_misses_total` |
| Backend retries | Retry rate by route, retry count over the selected range, proxy outcomes after retries | `gatekeeper_proxy_retries_total`, `gatekeeper_proxy_request_outcomes_total` |

The dashboard has four variables at the top: **Data source** (any Prometheus data source), **Tier**, **Client**, and **Route**. Tier and Client filter the rate-limiting panels, and Route filters the latency, cache, and retry panels.

## 1. Have Prometheus scrape Gatekeeper

Gatekeeper serves metrics on the same listener as the gateway (`server.listen_addr`, default `:8080`) at `metrics.path` (default `/metrics`). The endpoint is mounted outside the auth and rate-limit middleware, so Prometheus doesn't need an API key. Make sure `metrics.enabled: true` is set in your config.

Add a scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: gatekeeper
    metrics_path: /metrics          # match metrics.path
    static_configs:
      - targets: ["localhost:8080"] # host:port where Gatekeeper listens
```

Reload Prometheus, then open **Status → Targets** in the Prometheus UI and check that the `gatekeeper` target is `UP`.

## 2. Import the dashboard

1. In Grafana, open **Dashboards → New → Import**.
2. Click **Upload dashboard JSON file** and select `grafana/gatekeeper-dashboard.json`, or paste the file's contents into the text box.
3. Click **Load**, choose a folder if you like, then **Import**.
4. Use the **Data source** dropdown at the top of the dashboard to select the Prometheus data source that scrapes Gatekeeper. If Grafana doesn't have one yet, add it first under **Connections → Data sources → Add data source → Prometheus** and set the URL to your Prometheus server (for example `http://localhost:9090`).

Panels stay empty until Gatekeeper has served some traffic. To fill them quickly, use the load tester:

```bash
go run ./scripts/loadtest -target http://localhost:8080/api/ping -api-key demo-free-key -requests 200 -concurrency 20
```

## Optional: run Prometheus + Grafana locally with Docker Compose

[`docker-compose.monitoring.yml`](../docker-compose.monitoring.yml) adds Prometheus and Grafana to the existing compose stack. Grafana comes with the Prometheus data source and this dashboard already provisioned. The file is opt-in, so a plain `docker-compose up` still runs only the core stack.

```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up --build
```

- Grafana: <http://localhost:3000> (login `admin` / `admin`). The dashboard is under **Dashboards → Gatekeeper**.
- Prometheus: <http://localhost:9090>

The supporting config lives next to the dashboard:

```
grafana/
  gatekeeper-dashboard.json              the dashboard
  prometheus.yml                         scrape config (targets gatekeeper:8080/metrics)
  provisioning/datasources/prometheus.yml   Grafana → Prometheus data source
  provisioning/dashboards/gatekeeper.yml    loads the dashboard on startup
```

This setup is meant for local testing only. The Grafana credentials are the defaults, and Prometheus stores nothing persistently.

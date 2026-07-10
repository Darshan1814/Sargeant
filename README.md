y
# ULPF — Universal Log Pre-processing Framework
**SIH 2026 — PS 26156 — NTRO**

## Quick Start

```bash
git clone <repo-url>
cd ulpf
docker-compose up --build
```

| Service               | URL                        |
|-----------------------|----------------------------|
| Dashboard (React)     | http://localhost:3000       |
| Backend API (FastAPI) | http://localhost:8000/docs  |
| OpenSearch Dashboards | http://localhost:5601       |
| Grafana Ops           | http://localhost:3001       |
| Prometheus            | http://localhost:9090       |
| MinIO Console (raw archive) | http://localhost:9001 (minioadmin/minioadmin) |
| ClickHouse (analytics)| http://localhost:8123       |
| Kafka broker          | kafka:9092 (internal)       |

---

## Architecture

```
Collectors / HTTP ingest / Kafka producers (any source/format)
        │
        ▼
  Kafka  logs.raw          ← raw event bus (transport / buffer / replay)
        │        │
        │        └──────────────► MinIO  raw/<source>/<date>/<sha256>.log
        │                          (immutable archive → raw_object_id + sha256)
        ▼
  Parser Engine  /backend/pipeline.py
        │
   ┌────┴──────────────────────────────┐
   │ 1. Windows parser FAMILY (priority)│  ← syntax → schema → taxonomy
   │    /backend/windows/*.py           │     (evtx-text / XML / IIS W3C / firewall)
   │ 2. Fingerprint + NGRE registry     │  ← scores all parsers, best match ≥0.5
   │ 3. Drain3 template mining          │  ← unknown format fallback
   │ 4. DLQ (last resort)               │  ← 100% coverage guarantee
   └────┬───────────────────────────────┘
        ▼
  OCSF Mapping  /backend/ocsf_mapper.py   ← uniform envelope; Windows-native
        │                                    fields preserved under unmapped.windows
   ┌────┼───────────────┬──────────────┐
   ▼    ▼               ▼              ▼
DuckDB  OpenSearch   ClickHouse     Kafka logs.normalized / logs.dlq
(truth) (full-text)  (analytics,        │
                      raw_object_id  Prometheus → Grafana
                      linkage)
```

### Big-Data tier roles

| Component  | Role                                                        |
|------------|-------------------------------------------------------------|
| Kafka      | Streaming/transport/buffer/replay — NOT a database          |
| MinIO      | Immutable raw log archive + replay evidence (object store)  |
| ClickHouse | Normalized OCSF analytics/search/correlation store          |
| DuckDB     | Authoritative source-of-truth (works standalone, air-gapped)|

All three big-data services **degrade gracefully** — if they are down or absent,
the framework runs on DuckDB alone. This keeps a laptop demo and an air-gapped
deployment identical in behavior.

### Windows parser family (`/backend/windows/`)

Not one regex — a *family* following the Matryoshka model:
`detector.py` (which Windows format) → `envelope.py` (syntax → common schema) →
`handlers.py` (taxonomy: per-provider / per-Event-ID semantics) → `engine.py`.
One structural engine covers Security / System / Application / Sysmon /
PowerShell / Defender (evtx-text + raw event XML); IIS W3C and Windows Firewall
text have their own syntax engines but belong to the same family. **No Windows
field is ever dropped** — common fields map to OCSF, everything else is preserved
verbatim under `normalized.unmapped.windows`.

### Streaming ingest & replay

* Produce raw logs to Kafka topic `logs.raw`; the `kafka-consumer` worker runs
  them through the identical pipeline. `POST /api/ingest` still works too.
* `POST /api/replay/{event_id}` re-parses an event's ORIGINAL bytes from MinIO
  through the CURRENT parser set — fix a parser, re-normalize old events.
* `GET /api/analytics/summary` returns cross-source ClickHouse aggregates.

## Directory Structure

```
ulpf/
├── backend/
│   ├── main.py              # FastAPI app, all endpoints
│   ├── fingerprint.py       # Parser scoring / selection
│   ├── pipeline.py          # Full ingest pipeline
│   ├── ocsf_mapper.py       # Field mapping → OCSF schema
│   ├── db.py                # DuckDB storage layer
│   ├── opensearch_client.py # OpenSearch indexing & search
│   ├── requirements.txt
│   ├── Dockerfile
│   └── tests/
│       ├── test_pipeline.py  # 6 required tests
│       └── fixtures/         # Sample log files
├── parsers/
│   └── registry/
│       ├── WIN-EVTLOG-001.json
│       └── MAC-ULOG-001.json
├── ocsf/
│   └── schemas/              # Vendored OCSF schemas (no runtime fetch)
├── frontend/
│   └── src/pages/            # 6 React pages
├── prometheus/
│   └── prometheus.yml
├── grafana/
│   ├── provisioning/         # Auto-provisioned datasource + dashboard
│   └── dashboards/
└── docker-compose.yml
```

## Running Tests

```bash
docker-compose run backend pytest -v
```

All 6 tests must exit 0.

## Streaming ingest (Kafka)

Instead of HTTP, collectors can stream to the `logs.raw` topic; the
`kafka-consumer` container runs each record through the identical pipeline:

```bash
# a raw line, or a JSON envelope {"raw_log": "...", "source": "windows"}
echo '{"raw_log":"Log Name: Security\nEvent ID: 4625\n...","source":"windows"}' \
  | docker compose exec -T kafka \
    kafka-console-producer.sh --bootstrap-server localhost:9092 --topic logs.raw
```

## Air-gapped deployment

```bash
# on an internet-connected machine:
./scripts/offline-bundle.sh          # → dist/ulpf-airgap-bundle.tar.gz
# copy the bundle to the air-gapped host, then:
tar -xzf ulpf-airgap-bundle.tar.gz
docker load -i dist/ulpf-images.tar
docker compose up                    # no registry access required
```

OCSF schemas are vendored under `ocsf/` (no runtime fetch) and parsers are local
JSON, so the framework never reaches the internet at runtime.

## Adding a New Log Source

Drop a new JSON file into `parsers/registry/`:

```json
{
  "parser_id": "YOUR-PARSER-001",
  "source_name": "My Device",
  "os_family": "Linux",
  "category": "Network Activity",
  "ocsf_class_uid": 4001,
  "identifiers": {
    "required_substrings": ["keyword1", "keyword2"],
    "regex_signature": "your_signature_pattern",
    "confidence_weight": 0.9
  },
  "ngre_pattern": "^(?P<timestamp>[\\d-T:Z]+)\\s(?P<message>.*)$",
  "field_mapping": {
    "timestamp": "time",
    "message": "message"
  },
  "version": "1.0"
}
```

Restart the backend — no code changes required.

## Manual Verification Steps

1. Export a real Windows event: Event Viewer → right-click → Save All Events As → `.txt`
2. Go to http://localhost:3000 → drag the file into the Log Browser ingest area
3. Verify it appears with `parser_id: WIN-EVTLOG-001` and confidence > 80%
4. On macOS: `log show --last 5m > mac_logs.txt`, ingest via UI
5. Verify `parser_id: MAC-ULOG-001` in the dashboard

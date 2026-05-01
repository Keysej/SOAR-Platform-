# SOAR Platform — AI-Driven Security Orchestration & Automated Response

A portfolio project demonstrating end-to-end ML-powered security engineering across a realistic streaming data pipeline.

**Target roles:** AI/ML Engineer · Security Engineer · Data Engineering

---

## Architecture

```
Log Simulator
    │  JSON events (SSH logins, CloudTrail, firewall denies)
    ▼
Kafka  ──────────────────────────────────────────────────────────────────────────
  topic: security-logs-raw                            topic: security-alerts
    │                                                        ▲
    ├─► Kafka Consumer (pg_consumer.py)              Streaming Inference Service
    │       └─► PostgreSQL  (security_events)            (Isolation Forest)
    │       └─► Redis       (recent events + IP counts)
    │
    └─► FastAPI Ingestion API  (/ingest, /ingest/batch)

Remediation Orchestrator
    ├─► Block IP via AWS Security Groups (boto3)
    ├─► Isolate EC2 instance
    └─► Slack notification + manual override REST API

React + TypeScript + Tailwind Dashboard
    └─► WebSocket live feed · Alerts panel · System health · Manual overrides
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Event generation | Python 3.13 (log_generator.py) |
| Message bus | Apache Kafka 7.6 (Confluent) |
| Storage | PostgreSQL 16, Redis 7 |
| Ingestion API | FastAPI 0.115 + Uvicorn |
| ML / anomaly detection | scikit-learn (Isolation Forest) |
| Remediation | boto3 (AWS Security Groups, EC2) |
| Dashboard | React, TypeScript, Tailwind, WebSocket |
| Infrastructure | Docker + Colima, Terraform, AWS ECS/Fargate |
| CI/CD | GitHub Actions |

---

## Quick Start (Week 2 — local pipeline)

### Prerequisites

```bash
# Install Colima (Docker runtime for Intel/Apple Silicon Mac without Docker Desktop)
brew install colima docker docker-compose

# Start Colima
colima start --cpu 2 --memory 4
```

### 1 — Start infrastructure

```bash
cd deployment/docker
docker compose up -d

# Wait ~30 seconds, then verify all services are healthy
docker compose ps
```

Open [http://localhost:8090](http://localhost:8090) to browse Kafka topics in the UI.

### 2 — Install Python dependencies

```bash
cd /path/to/soar-platform
python3 -m venv .venv && source .venv/bin/activate
pip install -r ingestion/requirements.txt
```

### 3 — Start the Kafka → PostgreSQL consumer (Terminal 1)

```bash
source .venv/bin/activate
python ingestion/consumer/pg_consumer.py
```

### 4 — Stream events through the pipeline (Terminal 2)

```bash
source .venv/bin/activate
# Generate 200 events (5% anomaly rate, 10 events/sec) and pipe to Kafka
python ingestion/simulator/log_generator.py --count 200 --anomaly-rate 0.05 --eps 10 \
  | python ingestion/consumer/kafka_producer.py
```

### 5 — Ingest a Nessus scan CSV

```bash
source .venv/bin/activate
python ingestion/nessus_ingestor.py path/to/scan.csv
```

The script auto-classifies every finding as **block** (firewall rule), **patch** (software update), or **monitor** and loads them into the `vulnerabilities` table.

Start the API server and browse the dashboard endpoints:

```bash
uvicorn ingestion.api:app --reload
# GET  http://localhost:8000/vulns/summary
# GET  http://localhost:8000/vulns/block-list
# GET  http://localhost:8000/vulns/patch-list?risk=High
# GET  http://localhost:8000/vulns/by-host
# POST http://localhost:8000/ingest/nessus-csv  (multipart file upload)
```

### 6 — Verify data in PostgreSQL

```bash
docker exec -it soar-postgres psql -U soar -d soar_db -c \
  "SELECT event_type, status, anomaly, COUNT(*) FROM security_events GROUP BY 1,2,3 ORDER BY 4 DESC;"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `KAFKA_RAW_TOPIC` | `security-logs-raw` | Raw event topic |
| `DATABASE_URL` | `postgresql://soar:soar_password@localhost:5432/soar_db` | PostgreSQL DSN |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL |
| `BATCH_SIZE` | `50` | Consumer insert batch size |

---

## Project Structure

```
soar-platform/
├── ingestion/
│   ├── simulator/log_generator.py   # synthetic event producer
│   ├── consumer/kafka_producer.py   # stdin → Kafka
│   ├── consumer/pg_consumer.py      # Kafka → PostgreSQL + Redis
│   ├── api/main.py                  # FastAPI HTTP ingestion
│   └── requirements.txt
├── ml/
│   ├── notebooks/                   # Week 3: EDA + feature engineering
│   ├── models/                      # Week 4: serialized Isolation Forest
│   └── features/                    # feature extraction helpers
├── remediation/
│   ├── actions/                     # Week 6: boto3 AWS actions
│   └── orchestrator/                # alert → action router
├── dashboard/
│   ├── frontend/                    # Week 7: React + TypeScript + Tailwind
│   └── backend/                     # WebSocket relay server
├── deployment/
│   ├── docker/docker-compose.yml    # local dev stack
│   └── terraform/                   # Week 8: ECS/Fargate
├── tests/
└── .github/workflows/ci.yml
```

---

## 8-Week Build Plan

| Week | Goal | Status |
|---|---|---|
| 1 | Scaffold + log simulator | ✅ Done |
| 2 | Colima + Kafka + PostgreSQL pipeline + Nessus ingestor | ✅ Done |
| 3 | EDA + feature engineering (Jupyter) | ⬜ |
| 4 | Isolation Forest model + predict.py | ⬜ |
| 5 | Streaming inference microservice | ⬜ |
| 6 | Remediation orchestrator (AWS + Slack) | ⬜ |
| 7 | React + TypeScript dashboard (WebSocket) | ⬜ |
| 8 | Terraform + ECS/Fargate + CI/CD + demo | ⬜ |

---

*Built by Jimale Keyse — Information Security Analyst at St. Olaf College, CS + Data Science '28*

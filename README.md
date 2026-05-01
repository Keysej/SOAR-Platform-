# SOAR Platform — AI-Driven Security Orchestration & Automated Response

*Built by Jimale Keyse — Security Analyst*

---

## Quick Start

**Prerequisites:** [Colima](https://github.com/abiosoft/colima) + Docker

```bash
brew install colima docker docker-compose
colima start --cpu 2 --memory 4
```

**1. Start infrastructure**
```bash
cd deployment/docker
docker compose up -d
```

**2. Install dependencies**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r ingestion/requirements.txt
```

**3. Start the API + dashboard**
```bash
uvicorn ingestion.api.main:app --port 8000
```

Open [http://localhost:8000](http://localhost:8000) — upload a Nessus CSV scan and the dashboard auto-populates with block/patch/monitor findings and a printable report.

---

## Nessus CSV format

Export from Nessus: **Reports → Export → CSV**. Required columns: `CVE, Risk, Host, Protocol, Port, Name, Description, Solution`.

"""
SOAR Ingestion API + Dashboard

Routes:
    GET  /                      browser dashboard (upload, summary, tables)
    GET  /report                printable vulnerability report (RCE + Info Disclosure)
    GET  /report/data           JSON payload behind the report page
    GET  /health                liveness probe
    POST /ingest                single event → Kafka
    POST /ingest/batch          up to 1000 events → Kafka
    POST /ingest/nessus-csv     Nessus CSV upload → vulnerabilities table
    GET  /vulns/summary         counts by action × severity
    GET  /vulns/by-host         findings grouped by host
    GET  /vulns/block-list      firewall block candidates
    GET  /vulns/patch-list      software patch queue

Environment variables:
    KAFKA_BOOTSTRAP_SERVERS  default: localhost:9092
    KAFKA_RAW_TOPIC          default: security-logs-raw
    DATABASE_URL             default: postgresql://soar:soar_password@localhost:5432/soar_db
"""

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from kafka import KafkaProducer
from kafka.errors import KafkaError
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from nessus_ingestor import _classify, _DDL as _VULN_DDL  # noqa: E402

BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC             = os.getenv("KAFKA_RAW_TOPIC",          "security-logs-raw")
DATABASE_URL      = os.getenv(
    "DATABASE_URL",
    "postgresql://soar:soar_password@localhost:5432/soar_db",
)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

app = FastAPI(
    title="SOAR Platform",
    version="0.3.0",
    description="Vulnerability intelligence dashboard and event ingestion pipeline.",
)

_producer: KafkaProducer | None = None


def _get_producer() -> KafkaProducer:
    global _producer
    if _producer is None:
        _producer = KafkaProducer(
            bootstrap_servers=BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            acks="all",
            retries=3,
        )
    return _producer


def _get_db() -> psycopg2.extensions.connection:
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    except psycopg2.OperationalError as exc:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {exc}")


def _ensure_vuln_schema(conn: psycopg2.extensions.connection) -> None:
    with conn.cursor() as cur:
        cur.execute(_VULN_DDL)
    conn.commit()


# ---------------------------------------------------------------------------
# Remediation intelligence helpers
# ---------------------------------------------------------------------------

def _is_rce(name: str, cve: str | None) -> bool:
    n = name.lower()
    c = (cve or "").upper()
    return (
        any(kw in n for kw in ["remote code execution", "rce", "regresshion", "arbitrary code"])
        or c == "CVE-2024-6387"
        or ("openssh" in n and ("10.3" in n or "multiple vulnerabilities" in n))
    )


def _is_info_disclosure(name: str, cve: str | None) -> bool:
    n = name.lower()
    c = (cve or "").upper()
    return (
        any(kw in n for kw in ["disclosure", "password hash", "credential", "hash disclosure",
                                "information exposure", "cipher suite 0"])
        or c == "CVE-2013-4786"
    )


def _get_impact(name: str, cve: str | None) -> str:
    n = name.lower()
    c = (cve or "").upper()

    if c == "CVE-2024-6387" or ("regresshion" in n):
        return (
            "Unauthenticated remote attacker executes arbitrary code with root privileges. "
            "Full system compromise — data exfiltration, ransomware deployment, lateral movement."
        )
    if "openssh" in n and ("10.3" in n or "multiple" in n):
        return (
            "Bundle of memory-corruption and logic flaws in sshd. Severity varies by sub-CVE: "
            "ranges from privilege escalation to potential unauthenticated RCE under specific configurations."
        )
    if c == "CVE-2013-4786" or ("ipmi" in n and "password hash" in n):
        return (
            "Attacker on the management VLAN captures IPMI auth hashes via crafted RAKP messages, "
            "then cracks them offline (hashcat). Grants full BMC control: power cycle, firmware flash, OS console."
        )
    if "telnet" in n:
        return (
            "All traffic — including usernames and passwords — transmitted in cleartext over TCP. "
            "Any observer on the network passively captures credentials with zero effort."
        )
    if "modbus" in n or "coil" in n:
        return (
            "Unauthenticated read/write to OT device registers. "
            "Attacker can manipulate physical controls (HVAC, power, sensors) or disrupt operations."
        )
    if "ssl" in n or "tls" in n or "certificate" in n:
        return (
            "Encrypted communications exposed to MITM attacks or trust chain failures. "
            "Session tokens, credentials, and sensitive data at risk of interception."
        )
    return (
        "Unauthorized access or data leakage is possible depending on attacker network position. "
        "Severity confirmed by Nessus active scan."
    )


def _dedup_hosts(hosts: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for h in hosts:
        key = (h["host"], h["port"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def _group_findings(rows: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for r in rows:
        key = r["name"]
        if key not in grouped:
            grouped[key] = {
                "name":         r["name"],
                "cve":          r["cve"],
                "risk":         r["risk"],
                "description":  r["description"],
                "solution":     r["solution"],
                "action":       r["action"],
                "hosts":        [],
                "impact":       _get_impact(r["name"], r["cve"]),
                "reproducible": _get_reproducibility(r["name"], r["cve"], r["risk"]),
                "is_rce":       _is_rce(r["name"], r["cve"]),
                "is_info":      _is_info_disclosure(r["name"], r["cve"]),
            }
        grouped[key]["hosts"].append({"host": r["host"], "port": r["port"], "protocol": r["protocol"]})
    for f in grouped.values():
        f["hosts"] = _dedup_hosts(f["hosts"])
    return list(grouped.values())


def _get_reproducibility(name: str, cve: str | None, risk: str) -> str:
    n = name.lower()
    c = (cve or "").upper()

    if c == "CVE-2024-6387":
        return "Yes — Qualys published full PoC; multiple public exploit scripts on GitHub."
    if c == "CVE-2013-4786":
        return "Yes — ipmitool + hashcat reproduces this in under 5 min from any host with UDP/623 access."
    if "telnet" in n:
        return "Yes — Wireshark/tcpdump on local segment instantly confirms cleartext credential capture."
    if "modbus" in n:
        return "Yes — any Modbus/TCP client (mbtget, modbuspal) reads/writes registers without auth."
    if "openssh" in n and risk in ("High", "Critical"):
        return "Yes — Nessus version-check plugin confirmed; individual CVE PoC availability varies."
    if c and risk in ("High", "Critical"):
        return f"Yes — Nessus active scan confirmed; CVE {c} has public advisory."
    if risk in ("High", "Critical"):
        return "Yes — Nmap NSE scripts or Metasploit modules can independently verify."
    return "Likely — Nessus detection confirmed; may require specific network positioning to exploit."


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    event_type: str
    source_ip: str
    user: str | None = None
    status: str | None = None
    anomaly: bool = False
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, tags=["ui"], include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report", response_class=HTMLResponse, tags=["ui"], include_in_schema=False)
async def report_page(request: Request) -> HTMLResponse:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT cve, risk, host, protocol, port, name, description, solution, action
                FROM vulnerabilities
                ORDER BY
                    CASE risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                              WHEN 'Medium'   THEN 3 ELSE 4 END,
                    name
            """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    findings = _group_findings(rows)
    return templates.TemplateResponse("report.html", {
        "request":       request,
        "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "rce_findings":  [f for f in findings if f["is_rce"]],
        "info_findings": [f for f in findings if f["is_info"]],
        "total_findings": len(rows),
    })


# ---------------------------------------------------------------------------
# API — report data (JSON)
# ---------------------------------------------------------------------------

@app.get("/report/data", tags=["vulns"], summary="Structured report data (RCE + Info Disclosure)")
def report_data() -> dict[str, Any]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT cve, risk, host, protocol, port, name, description, solution, action
                FROM vulnerabilities
                ORDER BY CASE risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                                   WHEN 'Medium'   THEN 3 ELSE 4 END, name
            """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    findings = _group_findings(rows)
    return {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "rce_findings":   [f for f in findings if f["is_rce"]],
        "info_findings":  [f for f in findings if f["is_info"]],
        "total_findings": len(rows),
    }


# ---------------------------------------------------------------------------
# API — health + event ingestion
# ---------------------------------------------------------------------------

@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["ingest"],
    summary="Ingest a single security event",
)
def ingest(event: SecurityEvent) -> dict[str, Any]:
    try:
        _get_producer().send(TOPIC, value=event.model_dump())
    except KafkaError as exc:
        raise HTTPException(status_code=503, detail=f"Kafka unavailable: {exc}")
    return {"accepted": 1, "topic": TOPIC}


@app.post(
    "/ingest/batch",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["ingest"],
    summary="Ingest up to 1000 security events",
)
def ingest_batch(events: list[SecurityEvent]) -> dict[str, Any]:
    if len(events) > 1000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Batch size exceeds 1000 events.",
        )
    producer = _get_producer()
    try:
        for event in events:
            producer.send(TOPIC, value=event.model_dump())
        producer.flush()
    except KafkaError as exc:
        raise HTTPException(status_code=503, detail=f"Kafka unavailable: {exc}")
    return {"accepted": len(events), "topic": TOPIC}


_VULN_INSERT = """
INSERT INTO vulnerabilities
    (cve, risk, host, protocol, port, name, description, solution, action, source_file)
VALUES %s
ON CONFLICT DO NOTHING;
"""


@app.post(
    "/ingest/nessus-csv",
    status_code=status.HTTP_201_CREATED,
    tags=["ingest"],
    summary="Upload a Nessus CSV export → vulnerabilities table",
)
async def ingest_nessus_csv(file: UploadFile) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")

    raw     = await file.read()
    decoded = raw.decode("utf-8-sig")
    reader  = csv.DictReader(io.StringIO(decoded))
    rows: list[dict] = []

    for row in reader:
        risk = (row.get("Risk") or "").strip()
        if risk.lower() == "none":
            continue
        try:
            port = int((row.get("Port") or "").strip())
        except ValueError:
            port = 0
        name = (row.get("Name") or "").strip()
        rows.append({
            "cve":         (row.get("CVE") or "").strip() or None,
            "risk":        risk,
            "host":        (row.get("Host") or "").strip(),
            "protocol":    (row.get("Protocol") or "").strip() or None,
            "port":        port or None,
            "name":        name,
            "description": (row.get("Description") or "").strip() or None,
            "solution":    (row.get("Solution") or "").strip() or None,
            "action":      _classify(name, port, risk),
        })

    if not rows:
        return {"inserted": 0, "message": "No actionable findings in file."}

    conn = _get_db()
    _ensure_vuln_schema(conn)
    tuples = [
        (r["cve"], r["risk"], r["host"], r["protocol"], r["port"],
         r["name"], r["description"], r["solution"], r["action"], file.filename)
        for r in rows
    ]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, _VULN_INSERT, tuples)
    conn.commit()
    conn.close()

    from collections import Counter
    by_action = Counter(r["action"] for r in rows)
    return {
        "inserted": len(tuples),
        "source":   file.filename,
        "block":    by_action["block"],
        "patch":    by_action["patch"],
        "monitor":  by_action["monitor"],
    }


# ---------------------------------------------------------------------------
# API — vulnerability queries
# ---------------------------------------------------------------------------

@app.get("/vulns/summary", tags=["vulns"], summary="Aggregated counts by action and severity")
def vulns_summary() -> dict[str, Any]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT action, risk, COUNT(*) AS count
                FROM vulnerabilities
                GROUP BY action, risk
                ORDER BY
                    CASE action WHEN 'block' THEN 1 WHEN 'patch' THEN 2 ELSE 3 END,
                    CASE risk   WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                                WHEN 'Medium'   THEN 3 WHEN 'Low'  THEN 4 ELSE 5 END;
            """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"summary": rows, "total": sum(r["count"] for r in rows)}


@app.get("/vulns/by-host", tags=["vulns"], summary="Findings grouped by host")
def vulns_by_host(action: str | None = None) -> dict[str, Any]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if action:
                cur.execute("""
                    SELECT host, action, risk, port, name, cve
                    FROM vulnerabilities WHERE action = %s
                    ORDER BY host, CASE risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                                             WHEN 'Medium'   THEN 3 ELSE 4 END;
                """, (action,))
            else:
                cur.execute("""
                    SELECT host, action, risk, port, name, cve FROM vulnerabilities
                    ORDER BY host, CASE action WHEN 'block' THEN 1 WHEN 'patch' THEN 2 ELSE 3 END;
                """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    grouped: dict[str, list] = {}
    for r in rows:
        grouped.setdefault(r["host"], []).append(r)
    return {"hosts": grouped, "total_findings": len(rows)}


@app.get("/vulns/block-list", tags=["vulns"], summary="Hosts and ports requiring a network block")
def vulns_block_list() -> dict[str, Any]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT host, port, protocol, name, risk, cve, solution
                FROM vulnerabilities WHERE action = 'block'
                ORDER BY host, port;
            """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"action": "block", "items": rows, "count": len(rows)}


@app.get("/vulns/patch-list", tags=["vulns"], summary="Hosts requiring a software patch")
def vulns_patch_list(risk: str | None = None) -> dict[str, Any]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if risk:
                cur.execute("""
                    SELECT host, port, protocol, name, risk, cve, solution
                    FROM vulnerabilities WHERE action = 'patch' AND risk = %s
                    ORDER BY host, name;
                """, (risk,))
            else:
                cur.execute("""
                    SELECT host, port, protocol, name, risk, cve, solution
                    FROM vulnerabilities WHERE action = 'patch'
                    ORDER BY CASE risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                                       WHEN 'Medium'   THEN 3 ELSE 4 END, host, name;
                """)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"action": "patch", "items": rows, "count": len(rows)}

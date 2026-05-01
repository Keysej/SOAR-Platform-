#!/usr/bin/env python3
"""
Nessus CSV ingestor — loads scan results into PostgreSQL and auto-classifies
each finding as block / patch / monitor.

Usage:
    python ingestion/nessus_ingestor.py path/to/scan.csv

Expected CSV columns (standard Nessus export):
    CVE, Risk, Host, Protocol, Port, Name, Description, Solution

Environment variables:
    DATABASE_URL  default: postgresql://soar:soar_password@localhost:5432/soar_db
"""

import csv
import os
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://soar:soar_password@localhost:5432/soar_db",
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          SERIAL       PRIMARY KEY,
    cve         VARCHAR(30),
    risk        VARCHAR(20)  NOT NULL,
    host        VARCHAR(255) NOT NULL,
    protocol    VARCHAR(10),
    port        INTEGER,
    name        TEXT         NOT NULL,
    description TEXT,
    solution    TEXT,
    action      VARCHAR(10)  NOT NULL CHECK (action IN ('block','patch','monitor')),
    source_file VARCHAR(255),
    ingested_at TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vuln_host   ON vulnerabilities (host);
CREATE INDEX IF NOT EXISTS idx_vuln_action ON vulnerabilities (action);
CREATE INDEX IF NOT EXISTS idx_vuln_risk   ON vulnerabilities (risk);
"""

_INSERT = """
INSERT INTO vulnerabilities
    (cve, risk, host, protocol, port, name, description, solution, action, source_file)
VALUES %s
ON CONFLICT DO NOTHING;
"""


# ---------------------------------------------------------------------------
# Remediation classifier
# ---------------------------------------------------------------------------

_BLOCK_PORTS = {23, 502, 623}   # Telnet, Modbus, IPMI-over-LAN
_BLOCK_KEYWORDS = {"telnet", "modbus", "bacnet", "ipmi cipher suite 0", "unencrypted"}
_PATCH_RISKS = {"critical", "high", "medium"}


def _classify(name: str, port: int, risk: str) -> str:
    risk_lower  = risk.lower()
    name_lower  = name.lower()

    # Block: dangerous unencrypted/OT protocols or critical network exposure
    if port in _BLOCK_PORTS:
        return "block"
    if any(kw in name_lower for kw in _BLOCK_KEYWORDS):
        return "block"
    if "vnc" in name_lower and risk_lower in ("high", "critical"):
        return "block"

    # Monitor: informational / low severity
    if risk_lower in ("none", "info", "informational", "", "low"):
        return "monitor"

    # Patch: software CVEs needing an update (medium / high / critical)
    if risk_lower in _PATCH_RISKS:
        return "patch"

    return "monitor"


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def _parse_csv(path: Path) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            risk = (raw.get("Risk") or "").strip()
            if risk.lower() == "none":
                continue  # skip purely informational findings

            port_raw = (raw.get("Port") or "").strip()
            try:
                port = int(port_raw)
            except ValueError:
                port = 0

            name = (raw.get("Name") or "").strip()
            rows.append(
                {
                    "cve":         (raw.get("CVE") or "").strip() or None,
                    "risk":        risk,
                    "host":        (raw.get("Host") or "").strip(),
                    "protocol":    (raw.get("Protocol") or "").strip() or None,
                    "port":        port or None,
                    "name":        name,
                    "description": (raw.get("Description") or "").strip() or None,
                    "solution":    (raw.get("Solution") or "").strip() or None,
                    "action":      _classify(name, port, risk),
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _connect() -> psycopg2.extensions.connection:
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    except psycopg2.OperationalError as exc:
        print(f"[nessus] Cannot connect to PostgreSQL: {exc}", file=sys.stderr)
        sys.exit(1)


def _ensure_schema(conn: psycopg2.extensions.connection) -> None:
    with conn.cursor() as cur:
        cur.execute(_DDL)
    conn.commit()


def _load(
    conn: psycopg2.extensions.connection,
    rows: list[dict],
    source_file: str,
) -> int:
    tuples = [
        (
            r["cve"],
            r["risk"],
            r["host"],
            r["protocol"],
            r["port"],
            r["name"],
            r["description"],
            r["solution"],
            r["action"],
            source_file,
        )
        for r in rows
    ]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, _INSERT, tuples)
    conn.commit()
    return len(tuples)


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(rows: list[dict]) -> None:
    from collections import Counter

    by_action = Counter(r["action"] for r in rows)
    by_risk   = Counter(r["risk"]   for r in rows)

    print("\n── Remediation Summary ─────────────────────────────────", file=sys.stderr)
    print(f"  Total actionable findings : {len(rows)}", file=sys.stderr)
    print(f"  Block  (network block)    : {by_action['block']}", file=sys.stderr)
    print(f"  Patch  (update software)  : {by_action['patch']}", file=sys.stderr)
    print(f"  Monitor                   : {by_action['monitor']}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  By severity:", file=sys.stderr)
    for risk in ("Critical", "High", "Medium", "Low"):
        count = by_risk.get(risk, 0)
        if count:
            print(f"    {risk:<10} {count}", file=sys.stderr)

    blocks = [r for r in rows if r["action"] == "block"]
    if blocks:
        print("\n  Hosts to BLOCK:", file=sys.stderr)
        seen: set[str] = set()
        for r in blocks:
            key = f"{r['host']}:{r['port']}"
            if key not in seen:
                seen.add(key)
                print(f"    {r['host']:40s} port {r['port'] or '?':>5}  {r['name']}", file=sys.stderr)

    print("────────────────────────────────────────────────────────\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python ingestion/nessus_ingestor.py <path/to/scan.csv>", file=sys.stderr)
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        print(f"[nessus] File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[nessus] Parsing {csv_path.name}...", file=sys.stderr)
    rows = _parse_csv(csv_path)
    print(f"[nessus] {len(rows)} actionable findings parsed.", file=sys.stderr)

    if not rows:
        print("[nessus] Nothing to insert.", file=sys.stderr)
        return

    conn = _connect()
    _ensure_schema(conn)
    n = _load(conn, rows, csv_path.name)
    conn.close()

    print(f"[nessus] Inserted {n} rows into vulnerabilities table.", file=sys.stderr)
    _print_summary(rows)


if __name__ == "__main__":
    main()

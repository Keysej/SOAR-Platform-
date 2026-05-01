#!/usr/bin/env python3
"""
Kafka consumer — batches security events into PostgreSQL and caches in Redis.

- Reads from the 'security-logs-raw' Kafka topic
- Inserts events into the security_events table (auto-creates schema on first run)
- Caches the 1000 most-recent events and per-IP counters in Redis

Environment variables:
    KAFKA_BOOTSTRAP_SERVERS  default: localhost:9092
    KAFKA_RAW_TOPIC          default: security-logs-raw
    DATABASE_URL             default: postgresql://soar:soar_password@localhost:5432/soar_db
    REDIS_URL                default: redis://localhost:6379/0
    BATCH_SIZE               default: 50  (rows per INSERT batch)
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC             = os.getenv("KAFKA_RAW_TOPIC",          "security-logs-raw")
DATABASE_URL      = os.getenv("DATABASE_URL",             "postgresql://soar:soar_password@localhost:5432/soar_db")
REDIS_URL         = os.getenv("REDIS_URL",                "redis://localhost:6379/0")
BATCH_SIZE        = int(os.getenv("BATCH_SIZE", "50"))

# ---------------------------------------------------------------------------
# Schema — created automatically on first run
# ---------------------------------------------------------------------------
_DDL = """
CREATE TABLE IF NOT EXISTS security_events (
    id           UUID         PRIMARY KEY,
    timestamp    TIMESTAMPTZ  NOT NULL,
    event_type   VARCHAR(50),
    source_ip    INET,
    username     VARCHAR(255),
    status       VARCHAR(50),
    anomaly      BOOLEAN      DEFAULT FALSE,
    raw_payload  JSONB,
    ingested_at  TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_se_timestamp  ON security_events (timestamp  DESC);
CREATE INDEX IF NOT EXISTS idx_se_source_ip  ON security_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_se_event_type ON security_events (event_type);
"""

_INSERT = """
INSERT INTO security_events
    (id, timestamp, event_type, source_ip, username, status, anomaly, raw_payload)
VALUES %s
ON CONFLICT (id) DO NOTHING;
"""


# ---------------------------------------------------------------------------
# Connection helpers with retry
# ---------------------------------------------------------------------------

def _connect_db(url: str, retries: int = 6) -> psycopg2.extensions.connection:
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(url)
            conn.autocommit = False
            print("[consumer] Connected to PostgreSQL.", file=sys.stderr)
            return conn
        except psycopg2.OperationalError as exc:
            wait = 2 ** attempt
            print(
                f"[consumer] DB attempt {attempt}/{retries}: {exc}. Retrying in {wait}s...",
                file=sys.stderr,
            )
            time.sleep(wait)
    sys.exit(1)


def _connect_redis(url: str) -> redis.Redis:
    client = redis.from_url(url, decode_responses=True)
    client.ping()
    print("[consumer] Connected to Redis.", file=sys.stderr)
    return client


def _connect_kafka(retries: int = 6) -> KafkaConsumer:
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                TOPIC,
                bootstrap_servers=BOOTSTRAP_SERVERS,
                group_id="soar-pg-consumer",
                auto_offset_reset="earliest",   # replay from beginning if no offset saved
                enable_auto_commit=True,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=-1,          # block indefinitely waiting for messages
            )
            print(f"[consumer] Subscribed to '{TOPIC}'.", file=sys.stderr)
            return consumer
        except NoBrokersAvailable as exc:
            wait = 2 ** attempt
            print(
                f"[consumer] Kafka attempt {attempt}/{retries}: {exc}. Retrying in {wait}s...",
                file=sys.stderr,
            )
            time.sleep(wait)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

def _ensure_schema(conn: psycopg2.extensions.connection) -> None:
    with conn.cursor() as cur:
        cur.execute(_DDL)
    conn.commit()
    print("[consumer] Schema ready.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Batch flush
# ---------------------------------------------------------------------------

def _flush(
    conn: psycopg2.extensions.connection,
    redis_client: redis.Redis,
    batch: list[dict],
) -> int:
    rows = []
    for event in batch:
        rows.append((
            event.get("id") or str(uuid.uuid4()),
            event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event.get("event_type"),
            event.get("source_ip"),
            event.get("user"),           # generator uses "user"; schema column is "username"
            event.get("status"),
            bool(event.get("anomaly", False)),
            json.dumps(event),           # full payload stored for EDA / ML features
        ))

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, _INSERT, rows)
    conn.commit()

    # Redis: rolling window of last 1000 events + per-IP counters
    pipe = redis_client.pipeline()
    for event in batch:
        pipe.lpush("soar:recent_events", json.dumps(event))
        ip = event.get("source_ip")
        if ip:
            pipe.incr(f"soar:ip_count:{ip}")
            pipe.expire(f"soar:ip_count:{ip}", 3600)   # TTL = 1 hour
    pipe.ltrim("soar:recent_events", 0, 999)
    pipe.execute()

    return len(rows)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    conn         = _connect_db(DATABASE_URL)
    redis_client = _connect_redis(REDIS_URL)
    _ensure_schema(conn)

    consumer = _connect_kafka()

    batch: list[dict] = []
    total = 0

    print(f"[consumer] Waiting for messages (batch size = {BATCH_SIZE})...", file=sys.stderr)

    try:
        for message in consumer:
            batch.append(message.value)

            if len(batch) >= BATCH_SIZE:
                n = _flush(conn, redis_client, batch)
                total += n
                print(f"[consumer] Flushed {n} rows — total: {total}", file=sys.stderr)
                batch.clear()

    except KeyboardInterrupt:
        print("\n[consumer] Shutting down...", file=sys.stderr)
        if batch:
            n = _flush(conn, redis_client, batch)
            total += n
            print(f"[consumer] Final flush: {n} rows — total: {total}", file=sys.stderr)
    finally:
        consumer.close()
        conn.close()

    print(f"[consumer] Done. {total} total rows inserted.", file=sys.stderr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Reads JSON-line events from stdin (or a file) and publishes them to Kafka.

Usage:
    # pipe from generator
    python log_generator.py --count 500 | python kafka_producer.py

    # from a saved file
    python kafka_producer.py events.jsonl

Environment variables:
    KAFKA_BOOTSTRAP_SERVERS  default: localhost:9092
    KAFKA_RAW_TOPIC          default: security-logs-raw
"""

import json
import os
import sys
import time

from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable

BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = os.getenv("KAFKA_RAW_TOPIC", "security-logs-raw")
MAX_CONNECT_RETRIES = 6  # ~63 seconds of exponential back-off


def _build_producer(retries: int = MAX_CONNECT_RETRIES) -> KafkaProducer:
    """Connect to Kafka with exponential back-off — useful while containers start."""
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",          # wait for leader + replicas to acknowledge
                retries=3,           # retry failed sends up to 3 times
                linger_ms=10,        # small batching window for throughput
            )
            print(
                f"[producer] Connected to Kafka at {BOOTSTRAP_SERVERS}",
                file=sys.stderr,
            )
            return producer
        except NoBrokersAvailable as exc:
            wait = 2 ** attempt
            print(
                f"[producer] Attempt {attempt}/{retries} — no brokers yet ({exc}). "
                f"Retrying in {wait}s...",
                file=sys.stderr,
            )
            if attempt < retries:
                time.sleep(wait)

    print("[producer] ERROR: Could not connect to Kafka after all retries.", file=sys.stderr)
    sys.exit(1)


def main():
    source_path = sys.argv[1] if len(sys.argv) > 1 else None
    source = open(source_path) if source_path else sys.stdin

    producer = _build_producer()
    sent = skipped = 0

    try:
        for line in source:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[producer] Skipping malformed JSON: {exc}", file=sys.stderr)
                skipped += 1
                continue

            producer.send(TOPIC, value=event)
            sent += 1

            if sent % 100 == 0:
                print(f"[producer] Sent {sent} events...", file=sys.stderr)

    except KeyboardInterrupt:
        print("\n[producer] Interrupted.", file=sys.stderr)
    finally:
        producer.flush()
        if source_path:
            source.close()

    print(
        f"[producer] Done — sent {sent} events to '{TOPIC}' "
        f"({skipped} lines skipped).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Synthetic security-event generator for the SOAR pipeline.

Produces JSON-lines to stdout (or --output file) simulating:
  - SSH login attempts
  - AWS CloudTrail API calls
  - Firewall deny events

Each record matches the PostgreSQL security_events schema.
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone

EVENT_TYPES = ["ssh_login", "cloudtrail_event", "firewall_deny"]

USERNAMES = [
    "admin", "root", "ubuntu", "ec2-user", "deploy",
    "jdoe", "svc_account", "postgres", "git", "backup",
]

CLOUDTRAIL_ACTIONS = [
    "DescribeInstances", "RunInstances", "StopInstances",
    "CreateSecurityGroup", "AuthorizeSecurityGroupIngress",
    "GetSecretValue", "PutBucketPolicy", "DeleteBucket",
]

STATUSES = {
    "ssh_login":       ["success", "failed", "failed", "failed"],  # weighted toward failed
    "cloudtrail_event": ["success", "failed"],
    "firewall_deny":   ["denied"],
}

# IP prefixes associated with known Tor exit nodes / scanners (for anomaly simulation)
SUSPICIOUS_PREFIXES = ["185.220", "193.32", "45.33", "198.199", "89.234", "171.25"]


def _random_ip(anomalous: bool = False) -> str:
    if anomalous:
        prefix = random.choice(SUSPICIOUS_PREFIXES)
        return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_event(anomaly_rate: float) -> dict:
    is_anomaly = random.random() < anomaly_rate
    event_type = random.choice(EVENT_TYPES)

    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source_ip": _random_ip(anomalous=is_anomaly),
        "user": random.choice(USERNAMES),
        "status": random.choice(STATUSES[event_type]),
        "anomaly": is_anomaly,
    }

    # Attach richer metadata per event type (stored in raw_payload by consumer)
    if event_type == "ssh_login":
        event["metadata"] = {
            "port": 22,
            "auth_method": random.choice(["password", "publickey"]),
        }
    elif event_type == "cloudtrail_event":
        event["metadata"] = {
            "action": random.choice(CLOUDTRAIL_ACTIONS),
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
        }
    elif event_type == "firewall_deny":
        event["metadata"] = {
            "dst_port": random.choice([22, 3389, 5432, 6379, 80, 443, 8080]),
            "protocol": random.choice(["TCP", "UDP"]),
        }

    return event


def main():
    parser = argparse.ArgumentParser(
        description="SOAR synthetic log generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", type=int, default=100,
                        help="Number of events to generate")
    parser.add_argument("--anomaly-rate", type=float, default=0.05,
                        help="Fraction of events marked anomalous (0.0–1.0)")
    parser.add_argument("--eps", type=float, default=0.0,
                        help="Events per second — 0 means generate as fast as possible")
    parser.add_argument("--output", default="-",
                        help="Output file path; use - for stdout")
    args = parser.parse_args()

    if not (0.0 <= args.anomaly_rate <= 1.0):
        parser.error("--anomaly-rate must be between 0.0 and 1.0")

    out = open(args.output, "w") if args.output != "-" else sys.stdout
    delay = 1.0 / args.eps if args.eps > 0 else 0.0

    try:
        for _ in range(args.count):
            event = generate_event(args.anomaly_rate)
            out.write(json.dumps(event) + "\n")
            out.flush()
            if delay:
                time.sleep(delay)
    finally:
        if args.output != "-":
            out.close()

    total_anomalies = 0  # approximate — printed to stderr for visibility
    print(
        f"[generator] Done — {args.count} events written "
        f"(~{args.anomaly_rate:.0%} anomaly rate)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

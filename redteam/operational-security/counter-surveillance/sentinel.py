#!/usr/bin/env python3
"""Listen for counter-surveillance signals and escalate via stdout."""
from __future__ import annotations

import argparse
import json
import redis

CHANNELS = ["decoy_hits", "infrastructure_scans", "c2_probes"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    args = parser.parse_args()

    client = redis.Redis.from_url(args.redis_url)
    pubsub = client.pubsub()
    pubsub.subscribe(*CHANNELS)
    print(f"[sentinel] subscribed to {', '.join(CHANNELS)}")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        data = json.loads(message["data"])
        print(f"[ALERT] channel={message['channel'].decode()} data={data}")


if __name__ == "__main__":
    main()

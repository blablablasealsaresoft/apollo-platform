"""Example driver that streams telemetry from an IoT edge device."""
from __future__ import annotations

import asyncio
import random


async def stream(sensor_id: str):
    while True:
        payload = {
            "sensor": sensor_id,
            "temperature": round(random.uniform(18.0, 26.0), 2),
            "battery": random.randint(70, 100),
        }
        print(f"[driver] {payload}")
        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(stream("villager-edge-01"))

#!/usr/bin/env python3
"""Minimal C2 bridge for Cyberspike-Villager."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import grpc

# Placeholder proto import once available
# from apollo_pb2 import Beacon, Command
# from apollo_pb2_grpc import ControlStub


class _MockControlStub:
    async def SendBeacon(self, payload):  # type: ignore[override]
        print(f"[control] received beacon: {payload}")
        return {"command": "sleep", "interval": 15}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stub):
    addr = writer.get_extra_info("peername")
    print(f"[bridge] connection from {addr}")
    data = await reader.readline()
    beacon = json.loads(data.decode())
    response = await stub.SendBeacon(beacon)
    writer.write(json.dumps(response).encode() + b"\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def start_bridge(host: str, port: int, stub) -> None:
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, stub), host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[bridge] listening on {addrs}")
    async with server:
        await server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--bind", default="0.0.0.0:7000")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    host, port = args.bind.split(":")
    stub = _MockControlStub()
    asyncio.run(start_bridge(host, int(port), stub))


if __name__ == "__main__":
    main()

# Counter-Surveillance

Monitor telemetry (C2 check-ins, credential re-use, OSINT chatter) for indicators that the operation is being observed by defenders or third parties.

`sentinel.py` ingests log feeds (Redis pub/sub) and raises alerts when decoys are touched or infrastructure is fingerprinted.

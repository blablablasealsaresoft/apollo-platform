# Traffic Obfuscation

Reference implementations for blending C2 traffic with legitimate protocols (Domain Fronting, HTTP/2 jitter) to remain covert while sticking to authorized TTPs.

`traffic_shaper.py` proxies HTTP requests through rotating user-agents and jittered delays to mimic human usage.

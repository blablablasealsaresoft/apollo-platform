import asyncio
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from inference.real_time_analysis import RealTimeAnalysisEngine  # noqa: E402


class _MockModel:
    def predict_criminal_behavior(self, features):
        return {
            "is_criminal": True,
            "confidence": 0.91,
            "probability": 0.91,
            "risk_level": "HIGH",
            "feature_shape": tuple(features.shape),
        }


@pytest.mark.asyncio
async def test_analyze_behavior_returns_prediction():
    engine = RealTimeAnalysisEngine(_MockModel(), cache_enabled=False)
    result = await engine.analyze_behavior({"subject_id": "ignatova"})

    assert result["prediction"]["risk_level"] == "HIGH"
    assert result["within_sla"] is True
    assert result["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_batch_analyze_handles_multiple_events():
    engine = RealTimeAnalysisEngine(_MockModel(), cache_enabled=False)
    payload = [{"subject_id": f"subject-{i}"} for i in range(3)]

    results = await engine.batch_analyze(payload)

    assert len(results) == 3
    assert all("prediction" in r for r in results)


@pytest.mark.asyncio
async def test_performance_metrics_updated():
    engine = RealTimeAnalysisEngine(_MockModel(), cache_enabled=False)
    await engine.analyze_behavior({"subject_id": "metric-test"})
    metrics = engine.get_performance_metrics()

    assert metrics["total_predictions"] == 1
    assert 0 <= metrics["average_latency_ms"]

"""
Criminal Behavior AI - Real-Time Analysis Engine
Apollo Platform v0.1.0

Real-time inference engine for criminal behavior pattern detection.
Low-latency predictions with streaming data support.
"""

import asyncio
import numpy as np
from typing import Dict, List, Optional, AsyncGenerator
from datetime import datetime
import logging
from collections import deque
import redis.asyncio as aioredis
import json

logger = logging.getLogger(__name__)


class RealTimeAnalysisEngine:
    """
    Real-time criminal behavior analysis engine.

    Features:
    - Sub-100ms latency predictions
    - Streaming data processing
    - Redis caching for performance
    - Concurrent request handling
    - Automatic model scaling
    """

    def __init__(
        self,
        model,
        max_latency_ms: int = 100,
        cache_enabled: bool = True,
        redis_url: str = "redis://localhost:6379"
    ):
        """
        Initialize real-time analysis engine.

        Args:
            model: Trained prediction model
            max_latency_ms: Maximum acceptable latency (ms)
            cache_enabled: Enable Redis caching
            redis_url: Redis connection URL
        """
        self.model = model
        self.max_latency_ms = max_latency_ms
        self.cache_enabled = cache_enabled
        self.redis_url = redis_url
        self.redis_client = None

        # Performance monitoring
        self.prediction_count = 0
        self.total_latency = 0
        self.cache_hits = 0
        self.cache_misses = 0

        # Stream buffer
        self.stream_buffer = deque(maxlen=1000)

        logger.info(
            f"Initialized RealTimeAnalysisEngine: "
            f"max_latency={max_latency_ms}ms, cache={cache_enabled}"
        )

    async def initialize(self):
        """Initialize async components."""
        if self.cache_enabled:
            self.redis_client = await aioredis.from_url(
                self.redis_url,
                decode_responses=True
            )
            logger.info("Connected to Redis cache")

    async def analyze_behavior(
        self,
        behavior_data: Dict,
        use_cache: bool = True
    ) -> Dict:
        """
        Analyze behavior in real-time.

        Args:
            behavior_data: Behavioral data dictionary
            use_cache: Use cached prediction if available

        Returns:
            Prediction result with latency metrics
        """
        start_time = datetime.now()

        # Generate cache key
        cache_key = self._generate_cache_key(behavior_data)

        # Check cache
        if use_cache and self.cache_enabled:
            cached_result = await self._get_cached_prediction(cache_key)
            if cached_result is not None:
                self.cache_hits += 1
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000

                cached_result['cache_hit'] = True
                cached_result['latency_ms'] = latency_ms

                return cached_result

        self.cache_misses += 1

        # Prepare features
        features = self._prepare_features(behavior_data)

        # Run prediction
        prediction = await self._run_prediction(features)

        # Calculate latency
        latency_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Update metrics
        self.prediction_count += 1
        self.total_latency += latency_ms

        # Prepare result
        result = {
            'prediction': prediction,
            'latency_ms': latency_ms,
            'cache_hit': False,
            'timestamp': datetime.now().isoformat(),
            'within_sla': latency_ms <= self.max_latency_ms
        }

        # Cache result
        if self.cache_enabled:
            await self._cache_prediction(cache_key, result)

        # Check SLA
        if latency_ms > self.max_latency_ms:
            logger.warning(
                f"Prediction exceeded latency SLA: "
                f"{latency_ms:.2f}ms > {self.max_latency_ms}ms"
            )

        return result

    async def analyze_stream(
        self,
        data_stream: AsyncGenerator[Dict, None]
    ) -> AsyncGenerator[Dict, None]:
        """
        Analyze streaming behavioral data.

        Args:
            data_stream: Async generator of behavior data

        Yields:
            Real-time predictions
        """
        logger.info("Starting stream analysis")

        async for behavior_data in data_stream:
            # Add to buffer
            self.stream_buffer.append(behavior_data)

            # Analyze
            result = await self.analyze_behavior(behavior_data)

            yield result

    async def batch_analyze(
        self,
        behavior_batch: List[Dict],
        max_concurrent: int = 10
    ) -> List[Dict]:
        """
        Analyze batch of behaviors with concurrency control.

        Args:
            behavior_batch: List of behavior data dictionaries
            max_concurrent: Maximum concurrent predictions

        Returns:
            List of prediction results
        """
        logger.info(f"Batch analyzing {len(behavior_batch)} behaviors")

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(behavior_data):
            async with semaphore:
                return await self.analyze_behavior(behavior_data)

        # Execute concurrently
        tasks = [
            analyze_with_semaphore(behavior)
            for behavior in behavior_batch
        ]

        results = await asyncio.gather(*tasks)

        return results

    def _prepare_features(self, behavior_data: Dict) -> np.ndarray:
        """Prepare features from behavior data."""
        # This would be customized based on model requirements
        # For now, return dummy features
        return np.random.randn(30, 8)

    async def _run_prediction(self, features: np.ndarray) -> Dict:
        """
        Run model prediction asynchronously.

        Args:
            features: Feature array

        Returns:
            Prediction dictionary
        """
        # Run prediction in thread pool to avoid blocking
        loop = asyncio.get_event_loop()

        prediction = await loop.run_in_executor(
            None,
            self.model.predict_criminal_behavior,
            features
        )

        return prediction

    def _generate_cache_key(self, behavior_data: Dict) -> str:
        """Generate cache key from behavior data."""
        # Simple hash-based key
        data_str = json.dumps(behavior_data, sort_keys=True)
        return f"behavior:{hash(data_str)}"

    async def _get_cached_prediction(self, cache_key: str) -> Optional[Dict]:
        """Get prediction from cache."""
        if not self.redis_client:
            return None

        try:
            cached = await self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.error(f"Cache retrieval error: {e}")

        return None

    async def _cache_prediction(self, cache_key: str, result: Dict) -> None:
        """Cache prediction result."""
        if not self.redis_client:
            return

        try:
            # Cache for 1 hour
            await self.redis_client.setex(
                cache_key,
                3600,
                json.dumps(result)
            )
        except Exception as e:
            logger.error(f"Cache write error: {e}")

    def get_performance_metrics(self) -> Dict:
        """Get performance metrics."""
        avg_latency = (
            self.total_latency / self.prediction_count
            if self.prediction_count > 0
            else 0
        )

        cache_hit_rate = (
            self.cache_hits / (self.cache_hits + self.cache_misses)
            if (self.cache_hits + self.cache_misses) > 0
            else 0
        )

        return {
            'total_predictions': self.prediction_count,
            'average_latency_ms': avg_latency,
            'cache_hit_rate': cache_hit_rate,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'within_sla_rate': avg_latency <= self.max_latency_ms
        }

    async def shutdown(self):
        """Shutdown engine and cleanup resources."""
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")

        logger.info(f"Final metrics: {self.get_performance_metrics()}")


class StreamProcessor:
    """
    Process streaming criminal behavior data.

    Handles:
    - Continuous data ingestion
    - Real-time pattern detection
    - Alert generation
    - Performance optimization
    """

    def __init__(self, analysis_engine: RealTimeAnalysisEngine):
        """
        Initialize stream processor.

        Args:
            analysis_engine: Real-time analysis engine
        """
        self.engine = analysis_engine
        self.alert_threshold = 0.85
        self.alerts_generated = 0

        logger.info("Initialized StreamProcessor")

    async def process_stream(
        self,
        data_stream: AsyncGenerator[Dict, None],
        alert_callback: Optional[callable] = None
    ) -> None:
        """
        Process continuous stream of behavior data.

        Args:
            data_stream: Async generator of behavior data
            alert_callback: Callback function for alerts
        """
        logger.info("Starting stream processing")

        async for behavior_data in data_stream:
            # Analyze behavior
            result = await self.engine.analyze_behavior(behavior_data)

            # Check for alerts
            if result['prediction']['probability'] > self.alert_threshold:
                alert = self._generate_alert(behavior_data, result)

                self.alerts_generated += 1

                if alert_callback:
                    await alert_callback(alert)

                logger.warning(
                    f"ALERT: High-risk behavior detected - "
                    f"Probability: {result['prediction']['probability']:.3f}"
                )

    def _generate_alert(self, behavior_data: Dict, result: Dict) -> Dict:
        """Generate alert from high-risk detection."""
        return {
            'alert_id': f"ALERT-{self.alerts_generated + 1}",
            'timestamp': datetime.now().isoformat(),
            'risk_level': result['prediction']['risk_level'],
            'probability': result['prediction']['probability'],
            'confidence': result['prediction']['confidence'],
            'behavior_data': behavior_data,
            'recommended_action': self._recommend_action(result['prediction'])
        }

    def _recommend_action(self, prediction: Dict) -> str:
        """Recommend action based on prediction."""
        probability = prediction['probability']

        if probability > 0.95:
            return "IMMEDIATE_INVESTIGATION"
        elif probability > 0.85:
            return "ENHANCED_MONITORING"
        else:
            return "CONTINUED_MONITORING"


if __name__ == "__main__":
    # Example usage
    import asyncio

    async def main():
        logging.basicConfig(level=logging.INFO)

        # Mock model
        class MockModel:
            def predict_criminal_behavior(self, features):
                return {
                    'is_criminal': True,
                    'confidence': 0.9,
                    'probability': 0.9,
                    'risk_level': 'HIGH'
                }

        # Create engine
        engine = RealTimeAnalysisEngine(MockModel())
        await engine.initialize()

        # Test prediction
        behavior = {'transaction_frequency': 15}
        result = await engine.analyze_behavior(behavior)

        print(f"Prediction: {result}")
        print(f"Metrics: {engine.get_performance_metrics()}")

        await engine.shutdown()

    asyncio.run(main())

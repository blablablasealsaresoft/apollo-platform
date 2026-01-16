"""
Circuit Breaker Pattern Implementation
Provides fault tolerance and automatic failover for API calls
"""

import time
import asyncio
from enum import Enum
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit tripped, failing fast
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes to close from half-open
    timeout: float = 60.0  # Seconds to wait before half-open
    expected_exception: type = Exception
    fallback: Optional[Callable] = None


@dataclass
class CircuitStats:
    """Circuit breaker statistics"""
    state: CircuitState
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    last_state_change: float = field(default_factory=time.time)
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open"""
    pass


class CircuitBreaker:
    """Circuit breaker for fault tolerance"""

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        """
        Initialize circuit breaker

        Args:
            name: Circuit breaker identifier
            config: Configuration
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.stats = CircuitStats(state=CircuitState.CLOSED)
        self._lock = asyncio.Lock()

        logger.info(f"Initialized circuit breaker '{name}'")

    @property
    def state(self) -> CircuitState:
        """Get current state"""
        return self.stats.state

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerError: If circuit is open
        """
        async with self._lock:
            self.stats.total_calls += 1

            # Check if circuit should transition from OPEN to HALF_OPEN
            if self.stats.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    logger.warning(f"Circuit breaker '{self.name}' is OPEN")
                    if self.config.fallback:
                        return await self._execute_fallback(*args, **kwargs)
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' is OPEN"
                    )

        # Execute the function
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            await self._on_success()
            return result

        except self.config.expected_exception as e:
            await self._on_failure()
            raise

    async def _on_success(self):
        """Handle successful call"""
        async with self._lock:
            self.stats.success_count += 1
            self.stats.total_successes += 1
            self.stats.last_success_time = time.time()

            if self.stats.state == CircuitState.HALF_OPEN:
                if self.stats.success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self.stats.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.stats.failure_count = 0

    async def _on_failure(self):
        """Handle failed call"""
        async with self._lock:
            self.stats.failure_count += 1
            self.stats.total_failures += 1
            self.stats.last_failure_time = time.time()

            if self.stats.state == CircuitState.HALF_OPEN:
                self._transition_to_open()
            elif self.stats.state == CircuitState.CLOSED:
                if self.stats.failure_count >= self.config.failure_threshold:
                    self._transition_to_open()

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.stats.last_failure_time is None:
            return True

        elapsed = time.time() - self.stats.last_failure_time
        return elapsed >= self.config.timeout

    def _transition_to_open(self):
        """Transition to OPEN state"""
        self.stats.state = CircuitState.OPEN
        self.stats.last_state_change = time.time()
        self.stats.success_count = 0
        logger.warning(f"Circuit breaker '{self.name}' transitioned to OPEN")

    def _transition_to_half_open(self):
        """Transition to HALF_OPEN state"""
        self.stats.state = CircuitState.HALF_OPEN
        self.stats.last_state_change = time.time()
        self.stats.failure_count = 0
        self.stats.success_count = 0
        logger.info(f"Circuit breaker '{self.name}' transitioned to HALF_OPEN")

    def _transition_to_closed(self):
        """Transition to CLOSED state"""
        self.stats.state = CircuitState.CLOSED
        self.stats.last_state_change = time.time()
        self.stats.failure_count = 0
        self.stats.success_count = 0
        logger.info(f"Circuit breaker '{self.name}' transitioned to CLOSED")

    async def _execute_fallback(self, *args, **kwargs) -> Any:
        """Execute fallback function"""
        try:
            if asyncio.iscoroutinefunction(self.config.fallback):
                return await self.config.fallback(*args, **kwargs)
            else:
                return self.config.fallback(*args, **kwargs)
        except Exception as e:
            logger.error(f"Fallback failed for '{self.name}': {e}")
            raise

    def get_stats(self) -> Dict:
        """Get circuit breaker statistics"""
        return {
            'name': self.name,
            'state': self.stats.state.value,
            'failure_count': self.stats.failure_count,
            'success_count': self.stats.success_count,
            'total_calls': self.stats.total_calls,
            'total_failures': self.stats.total_failures,
            'total_successes': self.stats.total_successes,
            'last_failure_time': self.stats.last_failure_time,
            'last_success_time': self.stats.last_success_time,
            'time_in_current_state': time.time() - self.stats.last_state_change,
            'failure_rate': (
                self.stats.total_failures / self.stats.total_calls
                if self.stats.total_calls > 0 else 0
            )
        }

    async def reset(self):
        """Manually reset circuit breaker to CLOSED state"""
        async with self._lock:
            self._transition_to_closed()
            logger.info(f"Circuit breaker '{self.name}' manually reset")

    async def force_open(self):
        """Manually open circuit breaker"""
        async with self._lock:
            self._transition_to_open()
            logger.info(f"Circuit breaker '{self.name}' manually opened")


class CircuitBreakerManager:
    """Manages multiple circuit breakers"""

    def __init__(self):
        self.breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    async def get_breaker(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """
        Get or create circuit breaker

        Args:
            name: Breaker identifier
            config: Configuration

        Returns:
            Circuit breaker instance
        """
        async with self._lock:
            if name not in self.breakers:
                self.breakers[name] = CircuitBreaker(name, config)
            return self.breakers[name]

    async def call(
        self,
        name: str,
        func: Callable,
        *args,
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs
    ) -> Any:
        """
        Execute function with circuit breaker

        Args:
            name: Breaker identifier
            func: Function to execute
            config: Configuration
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result
        """
        breaker = await self.get_breaker(name, config)
        return await breaker.call(func, *args, **kwargs)

    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all circuit breakers"""
        return {
            name: breaker.get_stats()
            for name, breaker in self.breakers.items()
        }

    async def reset_all(self):
        """Reset all circuit breakers"""
        for breaker in self.breakers.values():
            await breaker.reset()
        logger.info("Reset all circuit breakers")

    def get_unhealthy_breakers(self) -> Dict[str, Dict]:
        """Get breakers that are not in CLOSED state"""
        return {
            name: breaker.get_stats()
            for name, breaker in self.breakers.items()
            if breaker.state != CircuitState.CLOSED
        }


class HealthChecker:
    """Health checking for services"""

    def __init__(self, check_interval: float = 30.0):
        """
        Initialize health checker

        Args:
            check_interval: Seconds between health checks
        """
        self.check_interval = check_interval
        self.health_checks: Dict[str, Callable] = {}
        self.health_status: Dict[str, bool] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def register(self, service: str, health_check: Callable):
        """
        Register health check for service

        Args:
            service: Service identifier
            health_check: Async function that returns bool
        """
        self.health_checks[service] = health_check
        logger.info(f"Registered health check for '{service}'")

    async def start(self):
        """Start health checking"""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._check_loop())
        logger.info("Started health checker")

    async def stop(self):
        """Stop health checking"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped health checker")

    async def _check_loop(self):
        """Health check loop"""
        while self._running:
            await self.check_all()
            await asyncio.sleep(self.check_interval)

    async def check_all(self):
        """Check health of all services"""
        for service, health_check in self.health_checks.items():
            try:
                is_healthy = await health_check()
                self.health_status[service] = is_healthy

                if not is_healthy:
                    logger.warning(f"Service '{service}' is unhealthy")

            except Exception as e:
                logger.error(f"Health check failed for '{service}': {e}")
                self.health_status[service] = False

    def get_status(self, service: str) -> Optional[bool]:
        """Get health status of service"""
        return self.health_status.get(service)

    def get_all_status(self) -> Dict[str, bool]:
        """Get health status of all services"""
        return self.health_status.copy()

    def is_healthy(self, service: str) -> bool:
        """Check if service is healthy"""
        return self.health_status.get(service, False)

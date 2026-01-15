"""
Pytest configuration and fixtures
"""

import pytest
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing"""
    class MockRedis:
        def __init__(self):
            self.data = {}

        def get(self, key):
            return self.data.get(key)

        def set(self, key, value):
            self.data[key] = value

        def setex(self, key, ttl, value):
            self.data[key] = value

        def incr(self, key):
            self.data[key] = self.data.get(key, 0) + 1
            return self.data[key]

        def delete(self, key):
            if key in self.data:
                del self.data[key]

        def expire(self, key, ttl):
            pass

    return MockRedis()


@pytest.fixture
def mock_elasticsearch():
    """Mock Elasticsearch client for testing"""
    class MockElasticsearch:
        def __init__(self):
            self.indices = MockIndices()
            self.data = {}

        def index(self, index, body, id=None):
            if index not in self.data:
                self.data[index] = []
            self.data[index].append(body)
            return {'_id': id or 'test_id'}

        def get(self, index, id):
            return {'_source': {}}

        def search(self, index, body):
            return {
                'hits': {
                    'total': {'value': 0},
                    'hits': []
                },
                'aggregations': {}
            }

    class MockIndices:
        def exists(self, index):
            return False

        def create(self, index, body):
            pass

    return MockElasticsearch()

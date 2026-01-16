"""
Unit tests for Sherlock OSINT Engine
"""

import pytest
import asyncio
from datetime import datetime
import sys
sys.path.append('..')

from osint_tools.sherlock import SherlockEngine, BatchUsernameProcessor


@pytest.mark.asyncio
async def test_sherlock_engine_initialization():
    """Test Sherlock engine initialization"""
    engine = SherlockEngine()
    assert engine is not None
    assert engine.get_platform_count() > 0
    assert 'Instagram' in engine.get_platforms()
    assert 'Twitter' in engine.get_platforms()
    assert 'GitHub' in engine.get_platforms()


@pytest.mark.asyncio
async def test_username_search():
    """Test single username search"""
    engine = SherlockEngine()

    # Test with a known username
    results = await engine.search_username('google', ['GitHub'])

    assert results is not None
    assert len(results) > 0

    # Check result structure
    result = results[0]
    assert hasattr(result, 'username')
    assert hasattr(result, 'platform')
    assert hasattr(result, 'url')
    assert hasattr(result, 'status')
    assert hasattr(result, 'confidence_score')


@pytest.mark.asyncio
async def test_batch_processor():
    """Test batch username search"""
    engine = SherlockEngine()
    processor = BatchUsernameProcessor(engine)

    usernames = ['google', 'microsoft', 'apple']
    platforms = ['GitHub', 'Twitter']

    batch_result = await processor.search_batch(usernames, platforms)

    assert batch_result is not None
    assert batch_result.total_usernames == len(usernames)
    assert batch_result.total_platforms == len(platforms)
    assert batch_result.total_results > 0


@pytest.mark.asyncio
async def test_username_variants():
    """Test username variant generation"""
    processor = BatchUsernameProcessor()

    variants = processor._generate_username_variants('john_doe')

    assert 'john_doe' in variants
    assert 'johndoe' in variants  # Without underscore
    assert len(variants) > 1


def test_export_json():
    """Test JSON export"""
    from osint_tools.sherlock import UsernameResult

    result = UsernameResult(
        username='test',
        platform='GitHub',
        url='https://github.com/test',
        status='found',
        confidence_score=0.95,
        response_time_ms=100,
        http_status=200,
        timestamp=datetime.now(),
        metadata={}
    )

    processor = BatchUsernameProcessor()

    # Create mock batch result
    from osint_tools.sherlock import BatchSearchResult

    batch_result = BatchSearchResult(
        total_usernames=1,
        total_platforms=1,
        total_results=1,
        found_results=1,
        not_found_results=0,
        error_results=0,
        start_time=datetime.now(),
        end_time=datetime.now(),
        duration_seconds=1.0,
        results_by_username={'test': [result]}
    )

    json_output = processor.export_results(batch_result, 'json')

    assert json_output is not None
    assert 'test' in json_output
    assert 'GitHub' in json_output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

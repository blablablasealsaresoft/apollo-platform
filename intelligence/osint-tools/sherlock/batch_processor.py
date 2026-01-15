"""
Batch Username Processor for Sherlock
Handles batch searches and parallel processing
"""

import asyncio
import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
from .sherlock_engine import SherlockEngine, UsernameResult

logger = logging.getLogger(__name__)


@dataclass
class BatchSearchResult:
    """Result from batch username search"""
    total_usernames: int
    total_platforms: int
    total_results: int
    found_results: int
    not_found_results: int
    error_results: int
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    results_by_username: Dict[str, List[UsernameResult]]


class BatchUsernameProcessor:
    """
    Batch processor for username searches
    Handles multiple usernames across multiple platforms
    """

    def __init__(
        self,
        sherlock_engine: Optional[SherlockEngine] = None,
        max_concurrent_usernames: int = 10,
        progress_callback: Optional[Callable] = None
    ):
        self.engine = sherlock_engine or SherlockEngine()
        self.max_concurrent_usernames = max_concurrent_usernames
        self.progress_callback = progress_callback

    async def search_batch(
        self,
        usernames: List[str],
        platforms: Optional[List[str]] = None
    ) -> BatchSearchResult:
        """
        Search multiple usernames across platforms

        Args:
            usernames: List of usernames to search
            platforms: List of platform names (None = all platforms)

        Returns:
            BatchSearchResult with aggregated results
        """
        start_time = datetime.now()
        logger.info(
            f"Starting batch search for {len(usernames)} usernames "
            f"across {len(platforms) if platforms else 'all'} platforms"
        )

        # Create semaphore for concurrent username searches
        semaphore = asyncio.Semaphore(self.max_concurrent_usernames)

        # Search each username
        tasks = [
            self._search_username_with_semaphore(
                username, platforms, semaphore, idx, len(usernames)
            )
            for idx, username in enumerate(usernames)
        ]

        results_list = await asyncio.gather(*tasks)

        # Aggregate results
        results_by_username = {
            username: results
            for username, results in zip(usernames, results_list)
        }

        # Calculate statistics
        total_results = sum(len(r) for r in results_list)
        found_results = sum(
            sum(1 for res in r if res.status == 'found')
            for r in results_list
        )
        not_found_results = sum(
            sum(1 for res in r if res.status == 'not_found')
            for r in results_list
        )
        error_results = sum(
            sum(1 for res in r if res.status in ['error', 'rate_limited'])
            for r in results_list
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        batch_result = BatchSearchResult(
            total_usernames=len(usernames),
            total_platforms=len(platforms) if platforms else self.engine.get_platform_count(),
            total_results=total_results,
            found_results=found_results,
            not_found_results=not_found_results,
            error_results=error_results,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            results_by_username=results_by_username
        )

        logger.info(
            f"Batch search completed in {duration:.2f}s: "
            f"{found_results} found, {not_found_results} not found, "
            f"{error_results} errors"
        )

        return batch_result

    async def _search_username_with_semaphore(
        self,
        username: str,
        platforms: Optional[List[str]],
        semaphore: asyncio.Semaphore,
        index: int,
        total: int
    ) -> List[UsernameResult]:
        """Search single username with semaphore control"""
        async with semaphore:
            logger.info(
                f"Searching username {index + 1}/{total}: {username}"
            )

            results = await self.engine.search_username(username, platforms)

            if self.progress_callback:
                self.progress_callback(index + 1, total, username, results)

            return results

    async def search_username_variants(
        self,
        base_username: str,
        variants: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None
    ) -> BatchSearchResult:
        """
        Search username variants (e.g., john_doe, johndoe, john.doe)

        Args:
            base_username: Base username
            variants: List of variant patterns (auto-generated if None)
            platforms: List of platform names

        Returns:
            BatchSearchResult with results for all variants
        """
        if variants is None:
            variants = self._generate_username_variants(base_username)
        else:
            # Combine base with variants
            all_usernames = [base_username] + variants
            return await self.search_batch(all_usernames, platforms)

        return await self.search_batch(variants, platforms)

    def _generate_username_variants(self, base_username: str) -> List[str]:
        """Generate common username variants"""
        variants = [base_username]

        # Remove special characters
        clean = base_username.replace('_', '').replace('.', '').replace('-', '')
        if clean != base_username:
            variants.append(clean)

        # Add common separators
        if '_' not in base_username and '.' not in base_username:
            parts = base_username.split()
            if len(parts) == 2:
                variants.extend([
                    f"{parts[0]}_{parts[1]}",
                    f"{parts[0]}.{parts[1]}",
                    f"{parts[0]}-{parts[1]}",
                    f"{parts[0]}{parts[1]}",
                ])

        # Add number variants
        for i in [1, 2, 123, 99]:
            variants.append(f"{base_username}{i}")

        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique_variants.append(v)

        return unique_variants

    async def search_related_usernames(
        self,
        known_usernames: List[str],
        platforms: Optional[List[str]] = None
    ) -> Dict[str, List[UsernameResult]]:
        """
        Search for usernames that might be related
        (e.g., variations of known usernames)

        Args:
            known_usernames: List of known usernames
            platforms: List of platform names

        Returns:
            Dictionary mapping potential usernames to results
        """
        # Generate variants for each known username
        all_variants = set()
        for username in known_usernames:
            variants = self._generate_username_variants(username)
            all_variants.update(variants)

        # Search all variants
        batch_result = await self.search_batch(
            list(all_variants),
            platforms
        )

        return batch_result.results_by_username

    def export_results(
        self,
        batch_result: BatchSearchResult,
        format: str = 'json'
    ) -> str:
        """
        Export batch results to various formats

        Args:
            batch_result: Batch search results
            format: Export format ('json', 'csv', 'markdown')

        Returns:
            Formatted string
        """
        if format == 'json':
            return self._export_json(batch_result)
        elif format == 'csv':
            return self._export_csv(batch_result)
        elif format == 'markdown':
            return self._export_markdown(batch_result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self, batch_result: BatchSearchResult) -> str:
        """Export to JSON"""
        import json
        from dataclasses import asdict

        data = {
            'summary': {
                'total_usernames': batch_result.total_usernames,
                'total_platforms': batch_result.total_platforms,
                'total_results': batch_result.total_results,
                'found_results': batch_result.found_results,
                'not_found_results': batch_result.not_found_results,
                'error_results': batch_result.error_results,
                'duration_seconds': batch_result.duration_seconds,
            },
            'results': {
                username: [asdict(r) for r in results]
                for username, results in batch_result.results_by_username.items()
            }
        }

        return json.dumps(data, indent=2, default=str)

    def _export_csv(self, batch_result: BatchSearchResult) -> str:
        """Export to CSV"""
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Username', 'Platform', 'URL', 'Status',
            'Confidence Score', 'Response Time (ms)',
            'HTTP Status', 'Timestamp'
        ])

        # Data rows
        for username, results in batch_result.results_by_username.items():
            for result in results:
                writer.writerow([
                    result.username,
                    result.platform,
                    result.url,
                    result.status,
                    result.confidence_score,
                    result.response_time_ms,
                    result.http_status,
                    result.timestamp
                ])

        return output.getvalue()

    def _export_markdown(self, batch_result: BatchSearchResult) -> str:
        """Export to Markdown"""
        lines = [
            "# Sherlock Batch Search Results",
            "",
            "## Summary",
            f"- Total Usernames: {batch_result.total_usernames}",
            f"- Total Platforms: {batch_result.total_platforms}",
            f"- Total Results: {batch_result.total_results}",
            f"- Found: {batch_result.found_results}",
            f"- Not Found: {batch_result.not_found_results}",
            f"- Errors: {batch_result.error_results}",
            f"- Duration: {batch_result.duration_seconds:.2f}s",
            "",
            "## Results by Username",
            ""
        ]

        for username, results in batch_result.results_by_username.items():
            found = [r for r in results if r.status == 'found']
            if found:
                lines.append(f"### {username}")
                lines.append(f"Found on {len(found)} platforms:")
                lines.append("")
                for result in found:
                    lines.append(
                        f"- [{result.platform}]({result.url}) "
                        f"(confidence: {result.confidence_score:.2f})"
                    )
                lines.append("")

        return "\n".join(lines)

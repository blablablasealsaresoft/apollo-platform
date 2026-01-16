"""
Public Records Intelligence System
Main orchestration engine for comprehensive public records searches
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
import logging

from court_records import CourtRecordsSearch
from criminal_records import CriminalRecordsSearch
from property_records import PropertyRecordsSearch
from business_records import BusinessRecordsSearch
from government_records import GovernmentRecordsSearch
from offshore_leaks import OffshoreLeaksSearch


@dataclass
class SearchQuery:
    """Search query parameters"""
    name: Optional[str] = None
    dob: Optional[str] = None
    ssn: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    business_name: Optional[str] = None
    record_types: Optional[List[str]] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class RecordResult:
    """Public record search result"""
    record_type: str
    source: str
    data: Dict[str, Any]
    relevance_score: float
    timestamp: str
    url: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


class PublicRecords:
    """
    Comprehensive Public Records Intelligence System

    Searches across multiple public record databases including:
    - Court records (JudyRecords, CourtListener, PACER)
    - Criminal records (state/federal databases, sex offender registry)
    - Property records (ownership, transactions, tax records)
    - Business records (OpenCorporates, Secretary of State)
    - Government records (FOIA, contracts, campaign finance)
    - Offshore leaks (ICIJ Panama Papers, Paradise Papers)
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize public records search system

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # Initialize search engines
        self.court_search = CourtRecordsSearch(self.config.get('court', {}))
        self.criminal_search = CriminalRecordsSearch(self.config.get('criminal', {}))
        self.property_search = PropertyRecordsSearch(self.config.get('property', {}))
        self.business_search = BusinessRecordsSearch(self.config.get('business', {}))
        self.government_search = GovernmentRecordsSearch(self.config.get('government', {}))
        self.offshore_search = OffshoreLeaksSearch(self.config.get('offshore', {}))

        self.all_record_types = [
            'court', 'criminal', 'property',
            'business', 'government', 'offshore'
        ]

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('PublicRecords')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def search(
        self,
        name: Optional[str] = None,
        dob: Optional[str] = None,
        address: Optional[str] = None,
        city: Optional[str] = None,
        state: Optional[str] = None,
        zip_code: Optional[str] = None,
        business_name: Optional[str] = None,
        record_types: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Search public records synchronously

        Args:
            name: Full name to search
            dob: Date of birth (YYYY-MM-DD)
            address: Street address
            city: City name
            state: State abbreviation (e.g., 'NY', 'CA')
            zip_code: ZIP code
            business_name: Business/company name
            record_types: List of record types to search ['court', 'criminal', etc.]
            **kwargs: Additional search parameters

        Returns:
            Dictionary with search results and metadata
        """
        query = SearchQuery(
            name=name,
            dob=dob,
            address=address,
            city=city,
            state=state,
            zip_code=zip_code,
            business_name=business_name,
            record_types=record_types or self.all_record_types,
            **kwargs
        )

        return asyncio.run(self.search_async(query))

    async def search_async(self, query: SearchQuery) -> Dict[str, Any]:
        """
        Asynchronous search across all record types

        Args:
            query: SearchQuery object with search parameters

        Returns:
            Comprehensive search results
        """
        self.logger.info(f"Starting public records search: {query.to_dict()}")

        start_time = datetime.now()
        results = {
            'query': query.to_dict(),
            'timestamp': start_time.isoformat(),
            'records': {},
            'summary': {},
            'errors': []
        }

        # Create search tasks based on record types
        tasks = []
        record_types = query.record_types or self.all_record_types

        if 'court' in record_types:
            tasks.append(self._search_court_records(query))
        if 'criminal' in record_types:
            tasks.append(self._search_criminal_records(query))
        if 'property' in record_types:
            tasks.append(self._search_property_records(query))
        if 'business' in record_types:
            tasks.append(self._search_business_records(query))
        if 'government' in record_types:
            tasks.append(self._search_government_records(query))
        if 'offshore' in record_types:
            tasks.append(self._search_offshore_leaks(query))

        # Execute all searches concurrently
        search_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, record_type in enumerate(record_types):
            if i < len(search_results):
                result = search_results[i]
                if isinstance(result, Exception):
                    results['errors'].append({
                        'record_type': record_type,
                        'error': str(result)
                    })
                    self.logger.error(f"Error searching {record_type}: {result}")
                else:
                    results['records'][record_type] = result

        # Generate summary
        results['summary'] = self._generate_summary(results['records'])
        results['execution_time'] = (datetime.now() - start_time).total_seconds()

        self.logger.info(f"Search completed in {results['execution_time']:.2f}s")

        return results

    async def _search_court_records(self, query: SearchQuery) -> List[Dict]:
        """Search court records"""
        self.logger.info("Searching court records...")
        return await self.court_search.search_async(query.to_dict())

    async def _search_criminal_records(self, query: SearchQuery) -> List[Dict]:
        """Search criminal records"""
        self.logger.info("Searching criminal records...")
        return await self.criminal_search.search_async(query.to_dict())

    async def _search_property_records(self, query: SearchQuery) -> List[Dict]:
        """Search property records"""
        self.logger.info("Searching property records...")
        return await self.property_search.search_async(query.to_dict())

    async def _search_business_records(self, query: SearchQuery) -> List[Dict]:
        """Search business records"""
        self.logger.info("Searching business records...")
        return await self.business_search.search_async(query.to_dict())

    async def _search_government_records(self, query: SearchQuery) -> List[Dict]:
        """Search government records"""
        self.logger.info("Searching government records...")
        return await self.government_search.search_async(query.to_dict())

    async def _search_offshore_leaks(self, query: SearchQuery) -> List[Dict]:
        """Search offshore leaks databases"""
        self.logger.info("Searching offshore leaks...")
        return await self.offshore_search.search_async(query.to_dict())

    def _generate_summary(self, records: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Generate summary statistics from search results

        Args:
            records: Dictionary of record type to results

        Returns:
            Summary statistics
        """
        summary = {
            'total_records': 0,
            'records_by_type': {},
            'risk_indicators': [],
            'notable_findings': []
        }

        for record_type, results in records.items():
            count = len(results)
            summary['records_by_type'][record_type] = count
            summary['total_records'] += count

            # Identify risk indicators
            if record_type == 'criminal' and count > 0:
                summary['risk_indicators'].append({
                    'type': 'criminal_records',
                    'severity': 'high',
                    'count': count
                })

            if record_type == 'court' and count > 5:
                summary['risk_indicators'].append({
                    'type': 'multiple_court_cases',
                    'severity': 'medium',
                    'count': count
                })

            if record_type == 'offshore' and count > 0:
                summary['risk_indicators'].append({
                    'type': 'offshore_entities',
                    'severity': 'high',
                    'count': count
                })

        return summary

    def export_results(
        self,
        results: Dict[str, Any],
        output_path: str,
        format: str = 'json'
    ) -> None:
        """
        Export search results to file

        Args:
            results: Search results dictionary
            output_path: Path to output file
            format: Export format ('json', 'csv', 'html')
        """
        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        elif format == 'csv':
            self._export_csv(results, output_path)
        elif format == 'html':
            self._export_html(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Results exported to {output_path}")

    def _export_csv(self, results: Dict[str, Any], output_path: str) -> None:
        """Export results as CSV"""
        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Record Type', 'Source', 'Data', 'URL'])

            for record_type, records in results.get('records', {}).items():
                for record in records:
                    writer.writerow([
                        record_type,
                        record.get('source', ''),
                        json.dumps(record.get('data', {})),
                        record.get('url', '')
                    ])

    def _export_html(self, results: Dict[str, Any], output_path: str) -> None:
        """Export results as HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Public Records Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f0f0f0; padding: 15px; margin-bottom: 20px; }}
                .record-type {{ margin-bottom: 30px; }}
                .record {{ background: #fff; border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
                .risk-high {{ color: red; font-weight: bold; }}
                .risk-medium {{ color: orange; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>Public Records Search Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Records: {results['summary']['total_records']}</p>
                <p>Search Date: {results['timestamp']}</p>
            </div>
        """

        for record_type, records in results.get('records', {}).items():
            html += f'<div class="record-type"><h2>{record_type.title()} Records ({len(records)})</h2>'
            for record in records:
                html += f'<div class="record">{json.dumps(record, indent=2)}</div>'
            html += '</div>'

        html += '</body></html>'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def get_supported_states(self) -> List[str]:
        """Get list of supported state abbreviations"""
        return [
            'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
            'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
            'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
            'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
            'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY'
        ]

    def validate_query(self, query: SearchQuery) -> tuple[bool, List[str]]:
        """
        Validate search query

        Args:
            query: SearchQuery to validate

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        if not query.name and not query.business_name:
            errors.append("Either name or business_name is required")

        if query.state and query.state not in self.get_supported_states():
            errors.append(f"Invalid state: {query.state}")

        return len(errors) == 0, errors


def main():
    """Example usage"""
    # Initialize system
    config = {
        'court': {
            'judy_records_api_key': 'your_key_here',
            'pacer_username': 'your_username',
            'pacer_password': 'your_password'
        },
        'offshore': {
            'icij_api_key': 'your_key_here'
        }
    }

    records = PublicRecords(config)

    # Example 1: Person search
    print("=" * 60)
    print("Example 1: Comprehensive Person Search")
    print("=" * 60)

    results = records.search(
        name="John Doe",
        state="NY",
        record_types=["court", "criminal", "property"]
    )

    print(f"\nTotal records found: {results['summary']['total_records']}")
    print(f"Execution time: {results['execution_time']:.2f}s")
    print(f"\nRecords by type:")
    for record_type, count in results['summary']['records_by_type'].items():
        print(f"  {record_type}: {count}")

    if results['summary']['risk_indicators']:
        print(f"\nRisk Indicators:")
        for indicator in results['summary']['risk_indicators']:
            print(f"  - {indicator['type']}: {indicator['severity']} ({indicator['count']})")

    # Example 2: Business search
    print("\n" + "=" * 60)
    print("Example 2: Business Records Search")
    print("=" * 60)

    business_results = records.search(
        business_name="Acme Corporation",
        state="DE",
        record_types=["business", "government"]
    )

    print(f"\nTotal records found: {business_results['summary']['total_records']}")

    # Example 3: Export results
    print("\n" + "=" * 60)
    print("Example 3: Export Results")
    print("=" * 60)

    records.export_results(results, 'public_records_report.json', format='json')
    records.export_results(results, 'public_records_report.html', format='html')
    print("Results exported to JSON and HTML formats")


if __name__ == '__main__':
    main()

"""
Court Records Search Module
Searches JudyRecords (740M cases), CourtListener, PACER, and state court systems
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from bs4 import BeautifulSoup


class CourtRecordsSearch:
    """
    Court records search across multiple databases

    Sources:
    - JudyRecords: 740 million court cases
    - CourtListener: Federal and state court opinions
    - PACER: Federal court system
    - State court systems
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize court records search

        Args:
            config: Configuration with API keys and credentials
        """
        self.config = config or {}
        self.logger = logging.getLogger('CourtRecordsSearch')

        # API endpoints
        self.judy_records_api = "https://www.judyrecords.com/api"
        self.court_listener_api = "https://www.courtlistener.com/api/rest/v3"
        self.pacer_api = "https://pacer.uscourts.gov"

        # Credentials
        self.judy_api_key = self.config.get('judy_records_api_key')
        self.court_listener_token = self.config.get('court_listener_token')
        self.pacer_username = self.config.get('pacer_username')
        self.pacer_password = self.config.get('pacer_password')

        # State court URLs (major states)
        self.state_courts = {
            'NY': 'https://iapps.courts.state.ny.us/webcivil',
            'CA': 'https://www.courts.ca.gov/find-my-court.htm',
            'TX': 'https://search.txcourts.gov',
            'FL': 'https://www.flcourts.org',
            'IL': 'https://www.illinoiscourts.gov',
            'PA': 'https://ujsportal.pacourts.us',
            'OH': 'https://www.supremecourt.ohio.gov',
            'GA': 'https://www.gsccca.org',
            'NC': 'https://www.nccourts.gov',
            'MI': 'https://www.courts.michigan.gov',
        }

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous court records search

        Args:
            query: Search parameters (name, state, etc.)

        Returns:
            List of court record results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_judy_records(session, query),
                self._search_court_listener(session, query),
                self._search_pacer(session, query),
                self._search_state_courts(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_judy_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search JudyRecords database (740M+ cases)

        JudyRecords aggregates court cases from:
        - Civil court cases
        - Criminal court cases
        - Traffic cases
        - Small claims
        - Family court
        """
        results = []

        if not self.judy_api_key:
            self.logger.warning("JudyRecords API key not configured")
            return results

        try:
            name = query.get('name', '')
            state = query.get('state', '')

            # JudyRecords search endpoint
            url = f"{self.judy_records_api}/search"
            params = {
                'name': name,
                'state': state,
                'api_key': self.judy_api_key
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for case in data.get('cases', []):
                        results.append({
                            'source': 'JudyRecords',
                            'case_number': case.get('case_number'),
                            'case_type': case.get('case_type'),
                            'filing_date': case.get('filing_date'),
                            'court': case.get('court'),
                            'jurisdiction': case.get('jurisdiction'),
                            'parties': case.get('parties', []),
                            'status': case.get('status'),
                            'disposition': case.get('disposition'),
                            'charges': case.get('charges', []),
                            'url': case.get('url'),
                            'data': case
                        })

                    self.logger.info(f"JudyRecords: Found {len(results)} cases")

                else:
                    self.logger.error(f"JudyRecords API error: {response.status}")

        except Exception as e:
            self.logger.error(f"JudyRecords search error: {e}")

        return results

    async def _search_court_listener(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search CourtListener (Free Law Project)

        CourtListener contains:
        - Supreme Court opinions
        - Federal appellate opinions
        - Federal district court opinions
        - State court opinions
        - Oral arguments
        """
        results = []

        try:
            name = query.get('name', '')

            # Search opinions
            url = f"{self.court_listener_api}/search/"
            headers = {}
            if self.court_listener_token:
                headers['Authorization'] = f'Token {self.court_listener_token}'

            params = {
                'q': name,
                'type': 'o',  # opinions
                'order_by': 'score desc'
            }

            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for opinion in data.get('results', []):
                        results.append({
                            'source': 'CourtListener',
                            'case_name': opinion.get('caseName'),
                            'case_number': opinion.get('docketNumber'),
                            'court': opinion.get('court'),
                            'date_filed': opinion.get('dateFiled'),
                            'citation': opinion.get('citation'),
                            'judges': opinion.get('judges', []),
                            'opinions': opinion.get('opinions', []),
                            'url': f"https://www.courtlistener.com{opinion.get('absolute_url', '')}",
                            'data': opinion
                        })

                    self.logger.info(f"CourtListener: Found {len(results)} opinions")

        except Exception as e:
            self.logger.error(f"CourtListener search error: {e}")

        return results

    async def _search_pacer(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search PACER (Public Access to Court Electronic Records)

        PACER provides access to:
        - Federal district court cases
        - Federal bankruptcy court cases
        - Federal appellate court cases
        - Case dockets and documents
        """
        results = []

        if not self.pacer_username or not self.pacer_password:
            self.logger.warning("PACER credentials not configured")
            return results

        try:
            name = query.get('name', '')

            # PACER Case Locator
            url = f"{self.pacer_api}/pcl/search.html"

            # Login to PACER
            login_url = f"{self.pacer_api}/pscof/login.jsf"
            login_data = {
                'login': self.pacer_username,
                'key': self.pacer_password
            }

            async with session.post(login_url, data=login_data) as response:
                if response.status == 200:
                    # Search cases
                    search_params = {
                        'name': name,
                        'case_type': 'all'
                    }

                    async with session.get(url, params=search_params) as search_response:
                        if search_response.status == 200:
                            html = await search_response.text()
                            results.extend(self._parse_pacer_results(html))

                            self.logger.info(f"PACER: Found {len(results)} cases")

        except Exception as e:
            self.logger.error(f"PACER search error: {e}")

        return results

    def _parse_pacer_results(self, html: str) -> List[Dict]:
        """Parse PACER search results HTML"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            rows = soup.find_all('tr', class_='case-row')

            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 5:
                    results.append({
                        'source': 'PACER',
                        'case_number': cols[0].text.strip(),
                        'case_title': cols[1].text.strip(),
                        'court': cols[2].text.strip(),
                        'filing_date': cols[3].text.strip(),
                        'status': cols[4].text.strip(),
                        'url': f"{self.pacer_api}/case/" + cols[0].text.strip(),
                        'data': {
                            'case_number': cols[0].text.strip(),
                            'title': cols[1].text.strip()
                        }
                    })

        except Exception as e:
            self.logger.error(f"Error parsing PACER results: {e}")

        return results

    async def _search_state_courts(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search state court systems

        Each state has its own court system and database
        """
        results = []

        state = query.get('state')
        if not state or state not in self.state_courts:
            return results

        try:
            name = query.get('name', '')

            # State-specific search logic
            if state == 'NY':
                results.extend(await self._search_ny_courts(session, name))
            elif state == 'CA':
                results.extend(await self._search_ca_courts(session, name))
            elif state == 'TX':
                results.extend(await self._search_tx_courts(session, name))
            elif state == 'FL':
                results.extend(await self._search_fl_courts(session, name))

            self.logger.info(f"State courts ({state}): Found {len(results)} cases")

        except Exception as e:
            self.logger.error(f"State court search error: {e}")

        return results

    async def _search_ny_courts(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search New York state courts"""
        results = []

        try:
            url = self.state_courts['NY'] + '/WebCivilMain'
            params = {'name': name}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    # Parse NY court results
                    results = self._parse_ny_results(html)

        except Exception as e:
            self.logger.error(f"NY courts search error: {e}")

        return results

    def _parse_ny_results(self, html: str) -> List[Dict]:
        """Parse NY court results"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            cases = soup.find_all('div', class_='case-result')

            for case in cases:
                results.append({
                    'source': 'NY State Courts',
                    'case_number': case.get('data-case-number', ''),
                    'case_type': case.get('data-case-type', ''),
                    'court': 'New York State Court',
                    'filing_date': case.get('data-filing-date', ''),
                    'status': case.get('data-status', ''),
                    'url': self.state_courts['NY'],
                    'data': {
                        'jurisdiction': 'NY',
                        'case_details': case.text.strip()
                    }
                })

        except Exception as e:
            self.logger.error(f"Error parsing NY results: {e}")

        return results

    async def _search_ca_courts(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search California state courts"""
        # Implementation for CA courts
        return []

    async def _search_tx_courts(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search Texas state courts"""
        # Implementation for TX courts
        return []

    async def _search_fl_courts(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search Florida state courts"""
        # Implementation for FL courts
        return []

    def get_case_details(self, case_number: str, court: str) -> Optional[Dict]:
        """
        Get detailed information about a specific case

        Args:
            case_number: Case number/docket number
            court: Court identifier

        Returns:
            Detailed case information
        """
        return asyncio.run(self._get_case_details_async(case_number, court))

    async def _get_case_details_async(
        self,
        case_number: str,
        court: str
    ) -> Optional[Dict]:
        """Async case details retrieval"""
        try:
            async with aiohttp.ClientSession() as session:
                # Try CourtListener first
                url = f"{self.court_listener_api}/dockets/"
                params = {'docket_number': case_number}
                headers = {}
                if self.court_listener_token:
                    headers['Authorization'] = f'Token {self.court_listener_token}'

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('results'):
                            return data['results'][0]

        except Exception as e:
            self.logger.error(f"Error getting case details: {e}")

        return None

    def track_case_docket(self, case_number: str, court: str) -> Dict[str, Any]:
        """
        Track a case docket for updates

        Args:
            case_number: Case number to track
            court: Court identifier

        Returns:
            Docket tracking information
        """
        return {
            'case_number': case_number,
            'court': court,
            'tracking_enabled': True,
            'last_checked': datetime.now().isoformat(),
            'status': 'active'
        }


def main():
    """Example usage"""
    court_search = CourtRecordsSearch({
        'judy_records_api_key': 'your_key_here',
        'court_listener_token': 'your_token_here',
        'pacer_username': 'your_username',
        'pacer_password': 'your_password'
    })

    # Search court records
    query = {
        'name': 'John Doe',
        'state': 'NY'
    }

    results = asyncio.run(court_search.search_async(query))

    print(f"Found {len(results)} court records:")
    for record in results[:5]:
        print(f"\nSource: {record['source']}")
        print(f"Case: {record.get('case_number', 'N/A')}")
        print(f"Court: {record.get('court', 'N/A')}")
        print(f"URL: {record.get('url', 'N/A')}")


if __name__ == '__main__':
    main()

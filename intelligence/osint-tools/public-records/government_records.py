"""
Government Records Search Module
Searches FOIA requests, government contracts, public salaries, campaign finance, lobbying
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging
from bs4 import BeautifulSoup
from datetime import datetime


class GovernmentRecordsSearch:
    """
    Government records search across multiple databases

    Sources:
    - FOIA requests and responses
    - USASpending.gov (government contracts)
    - Public employee salaries
    - FEC campaign finance data
    - Senate/House lobbying disclosures
    - Government employee databases
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize government records search

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger('GovernmentRecordsSearch')

        # API endpoints
        self.usaspending_api = "https://api.usaspending.gov/api/v2"
        self.fec_api = "https://api.open.fec.gov/v1"
        self.propublica_congress_api = "https://api.propublica.org/congress/v1"
        self.senate_lobby_api = "https://lda.senate.gov/api/v1"

        # API keys
        self.fec_api_key = self.config.get('fec_api_key')
        self.propublica_api_key = self.config.get('propublica_api_key')

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous government records search

        Args:
            query: Search parameters (name, business_name, etc.)

        Returns:
            List of government record results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_government_contracts(session, query),
                self._search_campaign_finance(session, query),
                self._search_lobbying_records(session, query),
                self._search_public_salaries(session, query),
                self._search_foia_requests(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_government_contracts(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search USASpending.gov for government contracts

        USASpending.gov tracks all federal spending including:
        - Contracts
        - Grants
        - Loans
        - Direct payments
        """
        results = []

        try:
            name = query.get('name', '')
            business_name = query.get('business_name', '')
            search_term = business_name or name

            if not search_term:
                return results

            # USASpending API search
            url = f"{self.usaspending_api}/search/spending_by_award"

            payload = {
                "filters": {
                    "keywords": [search_term],
                    "award_type_codes": ["A", "B", "C", "D"]  # Contracts
                },
                "fields": ["Award ID", "Recipient Name", "Award Amount", "Description"],
                "page": 1,
                "limit": 100,
                "sort": "Award Amount",
                "order": "desc"
            }

            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()

                    for award in data.get('results', []):
                        results.append({
                            'source': 'USASpending.gov',
                            'award_id': award.get('Award ID'),
                            'recipient_name': award.get('Recipient Name'),
                            'award_amount': award.get('Award Amount'),
                            'description': award.get('Description'),
                            'awarding_agency': award.get('Awarding Agency'),
                            'start_date': award.get('Start Date'),
                            'end_date': award.get('End Date'),
                            'contract_type': award.get('Award Type'),
                            'url': f"https://www.usaspending.gov/award/{award.get('Award ID')}",
                            'data': award
                        })

                    self.logger.info(f"Government contracts: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Government contracts search error: {e}")

        return results

    async def _search_campaign_finance(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search FEC (Federal Election Commission) campaign finance data

        Includes:
        - Campaign contributions
        - Candidate financial disclosures
        - Committee finances
        - Independent expenditures
        """
        results = []

        if not self.fec_api_key:
            self.logger.warning("FEC API key not configured")
            return results

        try:
            name = query.get('name', '')

            if not name:
                return results

            # Search individual contributions
            url = f"{self.fec_api}/schedules/schedule_a/"
            params = {
                'api_key': self.fec_api_key,
                'contributor_name': name,
                'per_page': 100,
                'sort': '-contribution_receipt_date'
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for contribution in data.get('results', []):
                        results.append({
                            'source': 'FEC Campaign Finance',
                            'contributor_name': contribution.get('contributor_name'),
                            'contribution_amount': contribution.get('contribution_receipt_amount'),
                            'contribution_date': contribution.get('contribution_receipt_date'),
                            'recipient_committee': contribution.get('committee', {}).get('name'),
                            'recipient_candidate': contribution.get('candidate_name'),
                            'employer': contribution.get('contributor_employer'),
                            'occupation': contribution.get('contributor_occupation'),
                            'city': contribution.get('contributor_city'),
                            'state': contribution.get('contributor_state'),
                            'zip': contribution.get('contributor_zip'),
                            'url': f"https://www.fec.gov/data/receipts/individual-contributions/?contributor_name={name}",
                            'data': contribution
                        })

            # Search candidates with matching name
            candidate_url = f"{self.fec_api}/candidates/search/"
            candidate_params = {
                'api_key': self.fec_api_key,
                'q': name,
                'per_page': 20
            }

            async with session.get(candidate_url, params=candidate_params) as response:
                if response.status == 200:
                    data = await response.json()

                    for candidate in data.get('results', []):
                        results.append({
                            'source': 'FEC Candidate',
                            'candidate_id': candidate.get('candidate_id'),
                            'name': candidate.get('name'),
                            'office': candidate.get('office_full'),
                            'party': candidate.get('party_full'),
                            'state': candidate.get('state'),
                            'district': candidate.get('district'),
                            'election_years': candidate.get('election_years', []),
                            'active_through': candidate.get('active_through'),
                            'url': f"https://www.fec.gov/data/candidate/{candidate.get('candidate_id')}",
                            'data': candidate
                        })

            self.logger.info(f"Campaign finance: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Campaign finance search error: {e}")

        return results

    async def _search_lobbying_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search lobbying disclosure records

        Sources:
        - Senate Lobbying Disclosure Act database
        - House lobbying registrations
        """
        results = []

        try:
            name = query.get('name', '')
            business_name = query.get('business_name', '')
            search_term = business_name or name

            if not search_term:
                return results

            # Senate LDA database
            url = f"{self.senate_lobby_api}/constants/filing/lobbyistnames"
            params = {'name': search_term}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for lobbyist in data.get('results', []):
                        results.append({
                            'source': 'Senate Lobbying Database',
                            'lobbyist_name': lobbyist.get('lobbyist_name'),
                            'registrant_name': lobbyist.get('registrant_name'),
                            'client_name': lobbyist.get('client_name'),
                            'filing_year': lobbyist.get('filing_year'),
                            'filing_period': lobbyist.get('filing_period'),
                            'income': lobbyist.get('income'),
                            'expenses': lobbyist.get('expenses'),
                            'url': 'https://lda.senate.gov/system/public/',
                            'data': lobbyist
                        })

            # Search registrants/clients
            registrant_url = f"{self.senate_lobby_api}/constants/filing/registrants"
            registrant_params = {'name': search_term}

            async with session.get(registrant_url, params=registrant_params) as response:
                if response.status == 200:
                    data = await response.json()

                    for registrant in data.get('results', []):
                        results.append({
                            'source': 'Senate Lobbying - Registrant',
                            'registrant_name': registrant.get('name'),
                            'address': registrant.get('address'),
                            'description': registrant.get('description'),
                            'url': 'https://lda.senate.gov/system/public/',
                            'data': registrant
                        })

            self.logger.info(f"Lobbying records: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Lobbying records search error: {e}")

        return results

    async def _search_public_salaries(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search public employee salary databases

        Sources:
        - Federal employee salaries (FedScope)
        - State employee salaries (varies by state)
        - Municipal employee salaries
        """
        results = []

        try:
            name = query.get('name', '')
            state = query.get('state')

            if not name:
                return results

            # Federal employee search (example)
            # FedScope OPM data
            federal_url = "https://www.fedsdatacenter.com/api/employees/search"
            params = {'name': name}

            # Note: This is a hypothetical endpoint
            # Actual implementation would vary by data source

            # State-specific salary databases
            if state:
                state_results = await self._search_state_salaries(session, name, state)
                results.extend(state_results)

            self.logger.info(f"Public salaries: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Public salaries search error: {e}")

        return results

    async def _search_state_salaries(
        self,
        session: aiohttp.ClientSession,
        name: str,
        state: str
    ) -> List[Dict]:
        """Search state employee salary databases"""
        results = []

        # State salary databases (examples)
        state_salary_dbs = {
            'CA': 'https://publicpay.ca.gov',
            'NY': 'https://www.seethroughny.net',
            'TX': 'https://salaries.texastribune.org',
            'FL': 'https://www.myfloridacfo.com/transparency',
            'IL': 'https://www.bettergov.org/news/public-employee-salary-database'
        }

        if state in state_salary_dbs:
            # State-specific implementation
            # Each state has different data formats
            pass

        return results

    async def _search_foia_requests(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search FOIA (Freedom of Information Act) requests and responses

        Sources:
        - FOIA.gov
        - MuckRock
        - DocumentCloud
        """
        results = []

        try:
            name = query.get('name', '')
            business_name = query.get('business_name', '')
            search_term = business_name or name

            if not search_term:
                return results

            # MuckRock FOIA search
            muckrock_url = "https://www.muckrock.com/api_v1/foia/"
            params = {
                'search': search_term,
                'ordering': '-date_updated'
            }

            async with session.get(muckrock_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for foia in data.get('results', []):
                        results.append({
                            'source': 'MuckRock FOIA',
                            'title': foia.get('title'),
                            'request_date': foia.get('date_submitted'),
                            'status': foia.get('status'),
                            'agency': foia.get('agency'),
                            'jurisdiction': foia.get('jurisdiction'),
                            'requester': foia.get('user'),
                            'url': foia.get('absolute_url'),
                            'data': foia
                        })

            self.logger.info(f"FOIA requests: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"FOIA search error: {e}")

        return results

    def get_government_profile(
        self,
        name: str,
        include_contracts: bool = True,
        include_campaign_finance: bool = True,
        include_lobbying: bool = True
    ) -> Dict[str, Any]:
        """
        Get comprehensive government records profile

        Args:
            name: Person or business name
            include_contracts: Include government contracts
            include_campaign_finance: Include campaign finance records
            include_lobbying: Include lobbying records

        Returns:
            Comprehensive government profile
        """
        query = {'name': name}
        results = asyncio.run(self.search_async(query))

        profile = {
            'subject': name,
            'search_date': datetime.now().isoformat(),
            'total_records': len(results),
            'records': results,
            'summary': {
                'government_contracts': 0,
                'total_contract_value': 0,
                'campaign_contributions': 0,
                'total_contributions': 0,
                'lobbying_activities': 0,
                'public_positions': 0
            }
        }

        # Calculate summary statistics
        for record in results:
            source = record.get('source', '')

            if 'USASpending' in source:
                profile['summary']['government_contracts'] += 1
                amount = record.get('award_amount', 0)
                if amount:
                    profile['summary']['total_contract_value'] += float(amount)

            if 'FEC' in source:
                profile['summary']['campaign_contributions'] += 1
                amount = record.get('contribution_amount', 0)
                if amount:
                    profile['summary']['total_contributions'] += float(amount)

            if 'Lobbying' in source:
                profile['summary']['lobbying_activities'] += 1

        return profile

    async def get_congressional_record(
        self,
        member_name: str
    ) -> Dict[str, Any]:
        """
        Get congressional member record

        Args:
            member_name: Name of congress member

        Returns:
            Congressional record information
        """
        record = {
            'name': member_name,
            'current_position': None,
            'voting_record': [],
            'sponsored_bills': [],
            'committee_assignments': [],
            'financial_disclosures': []
        }

        if not self.propublica_api_key:
            self.logger.warning("ProPublica API key not configured")
            return record

        try:
            async with aiohttp.ClientSession() as session:
                # Search for member
                url = f"{self.propublica_congress_api}/members.json"
                headers = {'X-API-Key': self.propublica_api_key}

                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Find matching member
                        for member in data.get('results', []):
                            if member_name.lower() in member.get('name', '').lower():
                                record['current_position'] = {
                                    'chamber': member.get('chamber'),
                                    'state': member.get('state'),
                                    'district': member.get('district'),
                                    'party': member.get('party'),
                                    'title': member.get('title')
                                }
                                break

        except Exception as e:
            self.logger.error(f"Congressional record search error: {e}")

        return record


def main():
    """Example usage"""
    gov_search = GovernmentRecordsSearch({
        'fec_api_key': 'your_key_here',
        'propublica_api_key': 'your_key_here'
    })

    # Example 1: Government contracts search
    print("=" * 60)
    print("Example 1: Government Contracts Search")
    print("=" * 60)

    query = {
        'business_name': 'Lockheed Martin'
    }

    results = asyncio.run(gov_search.search_async(query))

    print(f"Found {len(results)} government records:")
    for record in results[:3]:
        print(f"\nSource: {record['source']}")
        if 'award_amount' in record:
            print(f"Contract Amount: ${record['award_amount']:,.2f}")
        if 'contribution_amount' in record:
            print(f"Contribution: ${record['contribution_amount']:,.2f}")

    # Example 2: Government profile
    print("\n" + "=" * 60)
    print("Example 2: Comprehensive Government Profile")
    print("=" * 60)

    profile = gov_search.get_government_profile('John Doe')

    print(f"Subject: {profile['subject']}")
    print(f"Total Records: {profile['total_records']}")
    print(f"\nSummary:")
    print(f"  Government Contracts: {profile['summary']['government_contracts']}")
    print(f"  Total Contract Value: ${profile['summary']['total_contract_value']:,.2f}")
    print(f"  Campaign Contributions: {profile['summary']['campaign_contributions']}")
    print(f"  Total Contributions: ${profile['summary']['total_contributions']:,.2f}")
    print(f"  Lobbying Activities: {profile['summary']['lobbying_activities']}")


if __name__ == '__main__':
    main()

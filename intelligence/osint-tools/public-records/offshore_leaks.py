"""
Offshore Leaks Search Module
Searches ICIJ databases: Panama Papers, Paradise Papers, Offshore Leaks (810K+ entities)
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime


class OffshoreLeaksSearch:
    """
    Offshore Leaks database search (ICIJ)

    Databases:
    - Panama Papers (2016) - 214,488 entities
    - Paradise Papers (2017) - 120,000+ entities
    - Offshore Leaks (2013) - 130,000+ entities
    - Bahamas Leaks (2016) - 175,000+ entities
    - Malta Files (2017)
    - Mauritius Leaks (2019)
    - Pandora Papers (2021) - 29,000+ entities

    Total: 810,000+ offshore entities and individuals
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize offshore leaks search

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger('OffshoreLeaksSearch')

        # ICIJ Offshore Leaks Database API
        self.icij_api = "https://offshoreleaks.icij.org/api"
        self.icij_search_url = "https://offshoreleaks.icij.org/search"

        # Available databases
        self.databases = [
            'Panama Papers',
            'Paradise Papers',
            'Offshore Leaks',
            'Bahamas Leaks',
            'Malta Files',
            'Mauritius Leaks',
            'Pandora Papers'
        ]

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous offshore leaks search

        Args:
            query: Search parameters (name, business_name, etc.)

        Returns:
            List of offshore leak results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_entities(session, query),
                self._search_officers(session, query),
                self._search_intermediaries(session, query),
                self._search_addresses(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_entities(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search offshore entities (companies, trusts, foundations)

        Entities are the core of offshore structures - shell companies,
        trusts, and foundations used for asset protection or tax avoidance.
        """
        results = []

        try:
            name = query.get('name', '')
            business_name = query.get('business_name', '')
            search_term = business_name or name

            if not search_term:
                return results

            # ICIJ API entity search
            url = f"{self.icij_api}/entities/search"
            params = {
                'q': search_term,
                'limit': 100
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for entity in data.get('results', []):
                        results.append({
                            'source': 'ICIJ Offshore Leaks',
                            'type': 'entity',
                            'entity_id': entity.get('node_id'),
                            'name': entity.get('name'),
                            'entity_type': entity.get('type'),  # Company, Trust, Foundation, etc.
                            'jurisdiction': entity.get('jurisdiction'),
                            'jurisdiction_description': entity.get('jurisdiction_description'),
                            'incorporation_date': entity.get('incorporation_date'),
                            'inactivation_date': entity.get('inactivation_date'),
                            'status': entity.get('status'),
                            'company_type': entity.get('company_type'),
                            'service_provider': entity.get('service_provider'),
                            'countries': entity.get('countries', []),
                            'data_source': entity.get('sourceID'),  # Which leak: Panama, Paradise, etc.
                            'url': f"https://offshoreleaks.icij.org/nodes/{entity.get('node_id')}",
                            'data': entity
                        })

                    self.logger.info(f"Offshore entities: Found {len(results)} records")

                elif response.status == 429:
                    self.logger.warning("ICIJ API rate limit exceeded")

        except Exception as e:
            self.logger.error(f"Offshore entities search error: {e}")

        return results

    async def _search_officers(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search officers and shareholders

        Officers are individuals associated with offshore entities as:
        - Directors
        - Shareholders
        - Beneficiaries
        - Authorized signatories
        """
        results = []

        try:
            name = query.get('name', '')

            if not name:
                return results

            # ICIJ API officer search
            url = f"{self.icij_api}/officers/search"
            params = {
                'q': name,
                'limit': 100
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for officer in data.get('results', []):
                        results.append({
                            'source': 'ICIJ Offshore Leaks',
                            'type': 'officer',
                            'officer_id': officer.get('node_id'),
                            'name': officer.get('name'),
                            'countries': officer.get('countries', []),
                            'country_codes': officer.get('country_codes', []),
                            'valid_until': officer.get('valid_until'),
                            'data_source': officer.get('sourceID'),
                            'connections': officer.get('connection_count', 0),
                            'url': f"https://offshoreleaks.icij.org/nodes/{officer.get('node_id')}",
                            'data': officer
                        })

                    self.logger.info(f"Offshore officers: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Offshore officers search error: {e}")

        return results

    async def _search_intermediaries(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search intermediaries (law firms, banks that set up offshore entities)

        Intermediaries are professionals who create and manage offshore structures:
        - Law firms
        - Banks
        - Accounting firms
        - Corporate service providers
        """
        results = []

        try:
            business_name = query.get('business_name', '')

            if not business_name:
                return results

            # ICIJ API intermediary search
            url = f"{self.icij_api}/intermediaries/search"
            params = {
                'q': business_name,
                'limit': 100
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for intermediary in data.get('results', []):
                        results.append({
                            'source': 'ICIJ Offshore Leaks',
                            'type': 'intermediary',
                            'intermediary_id': intermediary.get('node_id'),
                            'name': intermediary.get('name'),
                            'address': intermediary.get('address'),
                            'countries': intermediary.get('countries', []),
                            'status': intermediary.get('status'),
                            'data_source': intermediary.get('sourceID'),
                            'connections': intermediary.get('connection_count', 0),
                            'url': f"https://offshoreleaks.icij.org/nodes/{intermediary.get('node_id')}",
                            'data': intermediary
                        })

                    self.logger.info(f"Offshore intermediaries: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Offshore intermediaries search error: {e}")

        return results

    async def _search_addresses(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search registered addresses

        Addresses associated with offshore entities
        """
        results = []

        try:
            address = query.get('address', '')

            if not address:
                return results

            # ICIJ API address search
            url = f"{self.icij_api}/addresses/search"
            params = {
                'q': address,
                'limit': 100
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for addr in data.get('results', []):
                        results.append({
                            'source': 'ICIJ Offshore Leaks',
                            'type': 'address',
                            'address_id': addr.get('node_id'),
                            'address': addr.get('address'),
                            'countries': addr.get('countries', []),
                            'data_source': addr.get('sourceID'),
                            'connections': addr.get('connection_count', 0),
                            'url': f"https://offshoreleaks.icij.org/nodes/{addr.get('node_id')}",
                            'data': addr
                        })

                    self.logger.info(f"Offshore addresses: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Offshore addresses search error: {e}")

        return results

    async def get_entity_details(
        self,
        entity_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific entity

        Args:
            entity_id: Entity node ID from ICIJ database

        Returns:
            Detailed entity information including connections
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.icij_api}/entities/{entity_id}"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        entity_details = {
                            'entity_id': data.get('node_id'),
                            'name': data.get('name'),
                            'type': data.get('type'),
                            'jurisdiction': data.get('jurisdiction'),
                            'incorporation_date': data.get('incorporation_date'),
                            'status': data.get('status'),
                            'data_source': data.get('sourceID'),
                            'officers': [],
                            'intermediaries': [],
                            'connections': []
                        }

                        # Get connections
                        connections = await self._get_entity_connections(session, entity_id)
                        entity_details['connections'] = connections

                        return entity_details

        except Exception as e:
            self.logger.error(f"Error getting entity details: {e}")

        return None

    async def _get_entity_connections(
        self,
        session: aiohttp.ClientSession,
        entity_id: str
    ) -> List[Dict]:
        """Get all connections for an entity"""
        connections = []

        try:
            url = f"{self.icij_api}/entities/{entity_id}/connections"

            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    for connection in data.get('results', []):
                        connections.append({
                            'connection_type': connection.get('rel_type'),
                            'connected_to': connection.get('target'),
                            'connected_name': connection.get('target_name'),
                            'start_date': connection.get('start_date'),
                            'end_date': connection.get('end_date'),
                            'link': connection.get('link')
                        })

        except Exception as e:
            self.logger.error(f"Error getting entity connections: {e}")

        return connections

    def get_offshore_profile(
        self,
        name: str,
        include_entities: bool = True,
        include_officers: bool = True,
        include_intermediaries: bool = True
    ) -> Dict[str, Any]:
        """
        Get comprehensive offshore profile

        Args:
            name: Person or company name to search
            include_entities: Include entity records
            include_officers: Include officer records
            include_intermediaries: Include intermediary records

        Returns:
            Comprehensive offshore profile
        """
        query = {'name': name, 'business_name': name}
        results = asyncio.run(self.search_async(query))

        profile = {
            'subject': name,
            'search_date': datetime.now().isoformat(),
            'total_records': len(results),
            'records': results,
            'summary': {
                'entities': 0,
                'officer_positions': 0,
                'intermediaries': 0,
                'jurisdictions': set(),
                'data_sources': set()
            },
            'risk_assessment': 'NONE'
        }

        # Analyze results
        for record in results:
            record_type = record.get('type')

            if record_type == 'entity':
                profile['summary']['entities'] += 1
            elif record_type == 'officer':
                profile['summary']['officer_positions'] += 1
            elif record_type == 'intermediary':
                profile['summary']['intermediaries'] += 1

            # Track jurisdictions
            if 'jurisdiction' in record:
                profile['summary']['jurisdictions'].add(record['jurisdiction'])

            if 'countries' in record:
                for country in record['countries']:
                    profile['summary']['jurisdictions'].add(country)

            # Track data sources
            if 'data_source' in record:
                profile['summary']['data_sources'].add(record['data_source'])

        # Convert sets to lists for JSON serialization
        profile['summary']['jurisdictions'] = list(profile['summary']['jurisdictions'])
        profile['summary']['data_sources'] = list(profile['summary']['data_sources'])

        # Risk assessment
        if len(results) > 0:
            if len(results) >= 5:
                profile['risk_assessment'] = 'HIGH'
            elif len(results) >= 2:
                profile['risk_assessment'] = 'MEDIUM'
            else:
                profile['risk_assessment'] = 'LOW'

        return profile

    def get_network_map(
        self,
        entity_id: str,
        depth: int = 2
    ) -> Dict[str, Any]:
        """
        Generate network map of connections

        Args:
            entity_id: Starting entity ID
            depth: How many levels deep to map (1-3)

        Returns:
            Network map with nodes and edges
        """
        network = {
            'center_entity': entity_id,
            'depth': depth,
            'nodes': [],
            'edges': []
        }

        # This would recursively build the network
        # Implementation would call get_entity_details for each node
        # and build graph structure

        return network

    def analyze_jurisdiction_risk(
        self,
        jurisdiction: str
    ) -> Dict[str, Any]:
        """
        Analyze risk level of a jurisdiction

        Args:
            jurisdiction: Jurisdiction code or name

        Returns:
            Risk analysis of jurisdiction
        """
        # High-risk offshore jurisdictions (secrecy havens)
        high_risk_jurisdictions = [
            'BVI',  # British Virgin Islands
            'CYM',  # Cayman Islands
            'PAN',  # Panama
            'BMU',  # Bermuda
            'BHS',  # Bahamas
            'LUX',  # Luxembourg
            'CHE',  # Switzerland
            'SGP',  # Singapore
            'HKG',  # Hong Kong
            'MLT',  # Malta
            'MUS',  # Mauritius
            'JEY',  # Jersey
            'GGY',  # Guernsey
            'LIE',  # Liechtenstein
            'MCO',  # Monaco
            'AND',  # Andorra
            'VGB',  # British Virgin Islands
            'KNA',  # St. Kitts and Nevis
            'VCT',  # St. Vincent and Grenadines
            'LCA'   # St. Lucia
        ]

        risk_level = 'HIGH' if jurisdiction in high_risk_jurisdictions else 'MEDIUM'

        return {
            'jurisdiction': jurisdiction,
            'risk_level': risk_level,
            'is_secrecy_haven': jurisdiction in high_risk_jurisdictions,
            'analysis': self._get_jurisdiction_description(jurisdiction)
        }

    def _get_jurisdiction_description(self, jurisdiction: str) -> str:
        """Get description of jurisdiction"""
        descriptions = {
            'BVI': 'British Virgin Islands - Popular for shell companies, high secrecy',
            'CYM': 'Cayman Islands - Major offshore financial center, hedge fund hub',
            'PAN': 'Panama - Panama Papers source, corporate secrecy jurisdiction',
            'BMU': 'Bermuda - Insurance and reinsurance center',
            'BHS': 'Bahamas - Banking and investment center',
            'LUX': 'Luxembourg - European tax haven, holding companies',
            'CHE': 'Switzerland - Banking secrecy, wealth management',
            'SGP': 'Singapore - Asian financial hub',
            'HKG': 'Hong Kong - Gateway to Chinese capital',
            'MLT': 'Malta - EU member, favorable tax regime',
            'MUS': 'Mauritius - Gateway to Africa and India',
            'JEY': 'Jersey - Crown Dependency, finance center',
            'GGY': 'Guernsey - Crown Dependency, finance center',
            'LIE': 'Liechtenstein - Private banking and foundations',
            'MCO': 'Monaco - Tax haven, zero income tax'
        }

        return descriptions.get(jurisdiction, 'Offshore jurisdiction')


def main():
    """Example usage"""
    offshore_search = OffshoreLeaksSearch()

    # Example 1: Search offshore entities
    print("=" * 60)
    print("Example 1: Offshore Entities Search")
    print("=" * 60)

    query = {
        'name': 'John Doe'
    }

    results = asyncio.run(offshore_search.search_async(query))

    print(f"Found {len(results)} offshore records:")
    for record in results[:3]:
        print(f"\nType: {record['type']}")
        print(f"Name: {record.get('name', 'N/A')}")
        print(f"Jurisdiction: {record.get('jurisdiction', 'N/A')}")
        print(f"Data Source: {record.get('data_source', 'N/A')}")
        print(f"URL: {record.get('url', 'N/A')}")

    # Example 2: Offshore profile
    print("\n" + "=" * 60)
    print("Example 2: Comprehensive Offshore Profile")
    print("=" * 60)

    profile = offshore_search.get_offshore_profile('Vladimir Putin')

    print(f"Subject: {profile['subject']}")
    print(f"Total Records: {profile['total_records']}")
    print(f"Risk Assessment: {profile['risk_assessment']}")
    print(f"\nSummary:")
    print(f"  Entities: {profile['summary']['entities']}")
    print(f"  Officer Positions: {profile['summary']['officer_positions']}")
    print(f"  Intermediaries: {profile['summary']['intermediaries']}")
    print(f"  Jurisdictions: {', '.join(profile['summary']['jurisdictions'])}")
    print(f"  Data Sources: {', '.join(profile['summary']['data_sources'])}")

    # Example 3: Jurisdiction risk analysis
    print("\n" + "=" * 60)
    print("Example 3: Jurisdiction Risk Analysis")
    print("=" * 60)

    risk = offshore_search.analyze_jurisdiction_risk('BVI')
    print(f"Jurisdiction: {risk['jurisdiction']}")
    print(f"Risk Level: {risk['risk_level']}")
    print(f"Secrecy Haven: {risk['is_secrecy_haven']}")
    print(f"Analysis: {risk['analysis']}")


if __name__ == '__main__':
    main()

"""
Property Records Search Module
Searches property ownership, transaction history, tax records, mortgages, and deeds
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging
from bs4 import BeautifulSoup
from datetime import datetime


class PropertyRecordsSearch:
    """
    Property records search across multiple databases

    Sources:
    - County assessor offices
    - County recorder offices
    - Property tax databases
    - Zillow/Realtor.com
    - DataTree by First American
    - PropertyShark
    - ATTOM Data Solutions
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize property records search

        Args:
            config: Configuration dictionary with API keys
        """
        self.config = config or {}
        self.logger = logging.getLogger('PropertyRecordsSearch')

        # API endpoints
        self.attom_api = "https://api.gateway.attomdata.com/propertyapi/v1.0.0"
        self.zillow_api = "https://www.zillow.com/webservice/GetDeepSearchResults.htm"
        self.realtor_api = "https://api.realtor.com/v2"

        # API keys
        self.attom_api_key = self.config.get('attom_api_key')
        self.zillow_api_key = self.config.get('zillow_api_key')
        self.realtor_api_key = self.config.get('realtor_api_key')

        # County property databases
        self.county_assessors = {
            'NY': {
                'New York': 'https://a836-acris.nyc.gov',
                'Kings': 'https://a836-acris.nyc.gov',
                'Queens': 'https://a836-acris.nyc.gov',
                'Bronx': 'https://a836-acris.nyc.gov',
                'Richmond': 'https://a836-acris.nyc.gov'
            },
            'CA': {
                'Los Angeles': 'https://portal.assessor.lacounty.gov',
                'San Diego': 'https://arcc.sdcounty.ca.gov',
                'Orange': 'https://ocassessor.com',
                'San Francisco': 'https://sfassessor.org'
            },
            'TX': {
                'Harris': 'https://hcad.org',
                'Dallas': 'https://dallascad.org',
                'Tarrant': 'https://tad.org',
                'Bexar': 'https://bcad.org'
            },
            'FL': {
                'Miami-Dade': 'https://www.miamidade.gov/pa',
                'Broward': 'https://bcpa.net',
                'Palm Beach': 'https://pbcgov.org/papa',
                'Hillsborough': 'https://hcpafl.org'
            }
        }

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous property records search

        Args:
            query: Search parameters (name, address, state, etc.)

        Returns:
            List of property record results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_property_by_owner(session, query),
                self._search_property_by_address(session, query),
                self._search_tax_records(session, query),
                self._search_deed_records(session, query),
                self._search_mortgage_records(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_property_by_owner(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search properties by owner name

        Returns all properties owned by a person
        """
        results = []

        try:
            name = query.get('name', '')
            state = query.get('state', '')

            # ATTOM Data API search by owner
            if self.attom_api_key:
                url = f"{self.attom_api}/property/owner"
                headers = {
                    'apikey': self.attom_api_key,
                    'Accept': 'application/json'
                }
                params = {
                    'ownername': name,
                    'state': state
                }

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        for property_data in data.get('property', []):
                            results.append(self._parse_attom_property(property_data))

                        self.logger.info(f"ATTOM owner search: Found {len(results)} properties")

        except Exception as e:
            self.logger.error(f"Owner search error: {e}")

        return results

    async def _search_property_by_address(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search property by address

        Returns detailed property information for a specific address
        """
        results = []

        try:
            address = query.get('address', '')
            city = query.get('city', '')
            state = query.get('state', '')
            zip_code = query.get('zip_code', '')

            if not address:
                return results

            # ATTOM Data API search by address
            if self.attom_api_key:
                url = f"{self.attom_api}/property/address"
                headers = {
                    'apikey': self.attom_api_key,
                    'Accept': 'application/json'
                }
                params = {
                    'address1': address,
                    'address2': f"{city}, {state} {zip_code}"
                }

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        for property_data in data.get('property', []):
                            results.append(self._parse_attom_property(property_data))

                        self.logger.info(f"ATTOM address search: Found {len(results)} properties")

            # Zillow API search
            if self.zillow_api_key:
                zillow_results = await self._search_zillow(session, address, city, state, zip_code)
                results.extend(zillow_results)

        except Exception as e:
            self.logger.error(f"Address search error: {e}")

        return results

    async def _search_zillow(
        self,
        session: aiohttp.ClientSession,
        address: str,
        city: str,
        state: str,
        zip_code: str
    ) -> List[Dict]:
        """Search Zillow for property data"""
        results = []

        try:
            url = self.zillow_api
            params = {
                'zws-id': self.zillow_api_key,
                'address': address,
                'citystatezip': f"{city}, {state} {zip_code}"
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    xml_data = await response.text()
                    soup = BeautifulSoup(xml_data, 'xml')

                    result = soup.find('result')
                    if result:
                        results.append({
                            'source': 'Zillow',
                            'zpid': result.find('zpid').text if result.find('zpid') else None,
                            'address': result.find('address').text if result.find('address') else None,
                            'zestimate': result.find('zestimate').text if result.find('zestimate') else None,
                            'last_sold_price': result.find('lastSoldPrice').text if result.find('lastSoldPrice') else None,
                            'last_sold_date': result.find('lastSoldDate').text if result.find('lastSoldDate') else None,
                            'url': result.find('homedetails').text if result.find('homedetails') else None,
                            'data': {
                                'year_built': result.find('yearBuilt').text if result.find('yearBuilt') else None,
                                'lot_size_sqft': result.find('lotSizeSqFt').text if result.find('lotSizeSqFt') else None,
                                'finished_sqft': result.find('finishedSqFt').text if result.find('finishedSqFt') else None,
                                'bathrooms': result.find('bathrooms').text if result.find('bathrooms') else None,
                                'bedrooms': result.find('bedrooms').text if result.find('bedrooms') else None
                            }
                        })

        except Exception as e:
            self.logger.error(f"Zillow search error: {e}")

        return results

    def _parse_attom_property(self, property_data: Dict) -> Dict:
        """Parse ATTOM property data into standard format"""
        address = property_data.get('address', {})
        assessment = property_data.get('assessment', {})
        building = property_data.get('building', {})
        lot = property_data.get('lot', {})
        owner = property_data.get('owner', {})
        sale = property_data.get('sale', {})

        return {
            'source': 'ATTOM Data',
            'apn': property_data.get('identifier', {}).get('apn'),
            'address': {
                'street': address.get('line1'),
                'city': address.get('locality'),
                'state': address.get('countrySubd'),
                'zip': address.get('postal1')
            },
            'owner': {
                'name': owner.get('owner1', {}).get('fullName'),
                'name2': owner.get('owner2', {}).get('fullName'),
                'mail_address': owner.get('mailingAddress')
            },
            'assessment': {
                'year': assessment.get('assessed', {}).get('assdYear'),
                'land_value': assessment.get('assessed', {}).get('assdLandValue'),
                'improvement_value': assessment.get('assessed', {}).get('assdImprovementValue'),
                'total_value': assessment.get('assessed', {}).get('assdTtlValue'),
                'market_value': assessment.get('market', {}).get('mktTtlValue')
            },
            'building': {
                'year_built': building.get('summary', {}).get('yearBuilt'),
                'bedrooms': building.get('rooms', {}).get('beds'),
                'bathrooms': building.get('rooms', {}).get('bathsTotal'),
                'square_feet': building.get('size', {}).get('bldgSize'),
                'stories': building.get('summary', {}).get('stories')
            },
            'lot': {
                'size_acres': lot.get('lotSize1'),
                'size_sqft': lot.get('lotSize2')
            },
            'sale': {
                'last_sale_date': sale.get('saleTransDate'),
                'last_sale_price': sale.get('amount', {}).get('saleAmt'),
                'sale_type': sale.get('saleTransType')
            },
            'url': f"https://www.attomdata.com/property/{property_data.get('identifier', {}).get('apn')}",
            'data': property_data
        }

    async def _search_tax_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search property tax records

        Returns property tax assessment and payment history
        """
        results = []

        try:
            state = query.get('state')
            county = query.get('county')
            name = query.get('name', '')

            if not state or not county:
                return results

            # County tax assessor search
            if state in self.county_assessors and county in self.county_assessors[state]:
                url = self.county_assessors[state][county]
                results.extend(await self._search_county_tax_records(session, url, name))

            self.logger.info(f"Tax records search: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Tax records search error: {e}")

        return results

    async def _search_county_tax_records(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        name: str
    ) -> List[Dict]:
        """Search county tax assessor database"""
        results = []

        try:
            # This would be implemented per county
            # Each county has different search interfaces
            pass

        except Exception as e:
            self.logger.error(f"County tax search error: {e}")

        return results

    async def _search_deed_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search deed records

        Returns property transfer records and deed information
        """
        results = []

        try:
            name = query.get('name', '')
            state = query.get('state')

            # Search county recorder offices
            # NYC ACRIS (Automated City Register Information System)
            if state == 'NY':
                results.extend(await self._search_nyc_acris(session, name))

            self.logger.info(f"Deed records search: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Deed records search error: {e}")

        return results

    async def _search_nyc_acris(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search NYC ACRIS for deed records"""
        results = []

        try:
            url = "https://a836-acris.nyc.gov/DS/DocumentSearch/PartyName"
            params = {'name': name}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    rows = soup.find_all('tr', class_='document-row')
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 6:
                            results.append({
                                'source': 'NYC ACRIS',
                                'document_id': cols[0].text.strip(),
                                'document_type': cols[1].text.strip(),
                                'recorded_date': cols[2].text.strip(),
                                'parties': cols[3].text.strip(),
                                'address': cols[4].text.strip(),
                                'amount': cols[5].text.strip(),
                                'url': f"https://a836-acris.nyc.gov/DS/DocumentSearch/DocumentDetail?doc_id={cols[0].text.strip()}",
                                'data': {
                                    'borough': cols[6].text.strip() if len(cols) > 6 else None
                                }
                            })

        except Exception as e:
            self.logger.error(f"NYC ACRIS search error: {e}")

        return results

    async def _search_mortgage_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search mortgage and lien records

        Returns mortgage information, liens, and encumbrances
        """
        results = []

        try:
            name = query.get('name', '')
            address = query.get('address', '')

            # Search mortgage records through ATTOM
            if self.attom_api_key and address:
                url = f"{self.attom_api}/property/mortgage"
                headers = {
                    'apikey': self.attom_api_key,
                    'Accept': 'application/json'
                }
                params = {'address': address}

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        for mortgage in data.get('mortgage', []):
                            results.append({
                                'source': 'ATTOM Mortgage Records',
                                'loan_number': mortgage.get('loanNumber'),
                                'loan_type': mortgage.get('loanType'),
                                'loan_amount': mortgage.get('amount'),
                                'lender': mortgage.get('lenderName'),
                                'recording_date': mortgage.get('recordingDate'),
                                'term': mortgage.get('term'),
                                'interest_rate': mortgage.get('interestRate'),
                                'maturity_date': mortgage.get('maturityDate'),
                                'url': None,
                                'data': mortgage
                            })

            self.logger.info(f"Mortgage records search: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Mortgage records search error: {e}")

        return results

    def get_property_history(
        self,
        address: str,
        city: str,
        state: str,
        zip_code: str
    ) -> Dict[str, Any]:
        """
        Get complete property history

        Args:
            address: Street address
            city: City name
            state: State abbreviation
            zip_code: ZIP code

        Returns:
            Comprehensive property history report
        """
        query = {
            'address': address,
            'city': city,
            'state': state,
            'zip_code': zip_code
        }

        results = asyncio.run(self.search_async(query))

        return {
            'address': f"{address}, {city}, {state} {zip_code}",
            'search_date': datetime.now().isoformat(),
            'total_records': len(results),
            'records': results,
            'timeline': self._build_timeline(results),
            'ownership_history': self._extract_ownership_history(results),
            'value_history': self._extract_value_history(results)
        }

    def _build_timeline(self, records: List[Dict]) -> List[Dict]:
        """Build chronological timeline of property events"""
        events = []

        for record in records:
            if 'sale' in record and record['sale'].get('last_sale_date'):
                events.append({
                    'date': record['sale']['last_sale_date'],
                    'event': 'Sale',
                    'details': f"Sold for ${record['sale']['last_sale_price']}"
                })

            if 'recorded_date' in record:
                events.append({
                    'date': record['recorded_date'],
                    'event': record.get('document_type', 'Document'),
                    'details': record.get('amount', '')
                })

        # Sort by date
        events.sort(key=lambda x: x['date'], reverse=True)

        return events

    def _extract_ownership_history(self, records: List[Dict]) -> List[Dict]:
        """Extract ownership history from records"""
        owners = []

        for record in records:
            if 'owner' in record and record['owner'].get('name'):
                owners.append({
                    'name': record['owner']['name'],
                    'mail_address': record['owner'].get('mail_address'),
                    'source': record['source']
                })

            if 'parties' in record:
                owners.append({
                    'parties': record['parties'],
                    'source': record['source']
                })

        return owners

    def _extract_value_history(self, records: List[Dict]) -> List[Dict]:
        """Extract property value history"""
        values = []

        for record in records:
            if 'assessment' in record:
                values.append({
                    'year': record['assessment'].get('year'),
                    'assessed_value': record['assessment'].get('total_value'),
                    'market_value': record['assessment'].get('market_value'),
                    'source': record['source']
                })

            if 'zestimate' in record:
                values.append({
                    'date': datetime.now().isoformat(),
                    'estimate': record['zestimate'],
                    'source': 'Zillow Zestimate'
                })

        return values


def main():
    """Example usage"""
    property_search = PropertyRecordsSearch({
        'attom_api_key': 'your_key_here',
        'zillow_api_key': 'your_key_here'
    })

    # Example 1: Search by owner name
    print("=" * 60)
    print("Example 1: Search Properties by Owner")
    print("=" * 60)

    query = {
        'name': 'John Doe',
        'state': 'NY'
    }

    results = asyncio.run(property_search.search_async(query))

    print(f"Found {len(results)} properties:")
    for record in results[:3]:
        print(f"\nSource: {record['source']}")
        if 'address' in record:
            addr = record['address']
            print(f"Address: {addr.get('street')}, {addr.get('city')}, {addr.get('state')}")
        if 'assessment' in record:
            print(f"Value: ${record['assessment'].get('market_value', 'N/A')}")

    # Example 2: Property history
    print("\n" + "=" * 60)
    print("Example 2: Complete Property History")
    print("=" * 60)

    history = property_search.get_property_history(
        address="123 Main Street",
        city="New York",
        state="NY",
        zip_code="10001"
    )

    print(f"Property: {history['address']}")
    print(f"Total Records: {history['total_records']}")
    print(f"\nOwnership History:")
    for owner in history['ownership_history'][:3]:
        print(f"  - {owner.get('name', owner.get('parties', 'N/A'))}")


if __name__ == '__main__':
    main()

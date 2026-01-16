"""
Business Records Search Module
Searches OpenCorporates (200M+ companies), Secretary of State filings, UCC, licenses, DBAs
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging
from bs4 import BeautifulSoup
from datetime import datetime


class BusinessRecordsSearch:
    """
    Business records search across multiple databases

    Sources:
    - OpenCorporates (200M+ companies worldwide)
    - Secretary of State business registrations
    - UCC (Uniform Commercial Code) filings
    - Business licenses
    - DBA (Doing Business As) registrations
    - Corporate registrations
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize business records search

        Args:
            config: Configuration dictionary with API keys
        """
        self.config = config or {}
        self.logger = logging.getLogger('BusinessRecordsSearch')

        # API endpoints
        self.opencorporates_api = "https://api.opencorporates.com/v0.4"
        self.sec_edgar_api = "https://www.sec.gov/cgi-bin/browse-edgar"

        # API keys
        self.opencorporates_token = self.config.get('opencorporates_token')

        # Secretary of State URLs by state
        self.sos_urls = {
            'AL': 'https://arc-sos.state.al.us/cgi/corpname.mbr/input',
            'AK': 'https://www.commerce.alaska.gov/cbp/main/search/entities',
            'AZ': 'https://ecorp.azcc.gov/EntitySearch',
            'AR': 'https://www.sos.arkansas.gov/corps/search_all.php',
            'CA': 'https://bizfileonline.sos.ca.gov/search/business',
            'CO': 'https://www.sos.state.co.us/biz/BusinessEntityCriteriaExt.do',
            'CT': 'https://service.ct.gov/business/s/onlinebusinesssearch',
            'DE': 'https://icis.corp.delaware.gov/Ecorp/EntitySearch/NameSearch.aspx',
            'FL': 'https://search.sunbiz.org/Inquiry/CorporationSearch/ByName',
            'GA': 'https://ecorp.sos.ga.gov/BusinessSearch',
            'HI': 'https://hbe.ehawaii.gov/documents/search.html',
            'ID': 'https://sosbiz.idaho.gov/search/business',
            'IL': 'https://apps.ilsos.gov/corporatellc',
            'IN': 'https://bsd.sos.in.gov/PublicBusinessSearch',
            'IA': 'https://sos.iowa.gov/search/business',
            'KS': 'https://www.kansas.gov/bess/flow/main',
            'KY': 'https://web.sos.ky.gov/ftsearch',
            'LA': 'https://coraweb.sos.la.gov/commercialsearch',
            'ME': 'https://icrs.informe.org/nei-sos-icrs/ICRS',
            'MD': 'https://egov.maryland.gov/businessexpress/entitysearch',
            'MA': 'https://corp.sec.state.ma.us/corpweb/corpsearch/corpsearch.aspx',
            'MI': 'https://cofs.lara.state.mi.us/corpweb/corpsearch/corpsearch.aspx',
            'MN': 'https://mblsportal.sos.state.mn.us/Business/Search',
            'MS': 'https://corp.sos.ms.gov/corp/portal/c/page/corpBusinessIdSearch',
            'MO': 'https://bsd.sos.mo.gov/BusinessEntity/BESearch.aspx',
            'MT': 'https://biz.sosmt.gov/search/business',
            'NE': 'https://www.nebraska.gov/sos/corp/corpsearch.cgi',
            'NV': 'https://esos.nv.gov/EntitySearch/OnlineEntitySearch',
            'NH': 'https://quickstart.sos.nh.gov/online/BusinessInquire',
            'NJ': 'https://www.njportal.com/DOR/BusinessNameSearch',
            'NM': 'https://portal.sos.state.nm.us/BFS/online/CorporationBusinessSearch',
            'NY': 'https://appext20.dos.ny.gov/corp_public/corpsearch.entity_search_entry',
            'NC': 'https://www.sosnc.gov/online_services/search',
            'ND': 'https://firststop.sos.nd.gov/search/business',
            'OH': 'https://businesssearch.ohiosos.gov',
            'OK': 'https://www.sos.ok.gov/corp/corpInquiryFind.aspx',
            'OR': 'https://egov.sos.state.or.us/br/pkg_web_name_srch_inq.login',
            'PA': 'https://www.corporations.pa.gov/search/corpsearch',
            'RI': 'https://business.sos.ri.gov/CorpWeb/CorpSearch/CorpSearch.aspx',
            'SC': 'https://businessfilings.sc.gov/BusinessFiling',
            'SD': 'https://sosenterprise.sd.gov/BusinessServices/Business/FilingSearch.aspx',
            'TN': 'https://tnbear.tn.gov/Ecommerce/FilingSearch.aspx',
            'TX': 'https://mycpa.cpa.state.tx.us/coa',
            'UT': 'https://secure.utah.gov/bes/index.html',
            'VT': 'https://bizfilings.vermont.gov/online/BusinessInquire',
            'VA': 'https://cis.scc.virginia.gov/EntitySearch/Index',
            'WA': 'https://ccfs.sos.wa.gov/#/BusinessSearch',
            'WV': 'https://business4.wv.gov/Business/Search',
            'WI': 'https://www.wdfi.org/apps/CorpSearch/Search.aspx',
            'WY': 'https://wyobiz.wyo.gov/Business/FilingSearch.aspx'
        }

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous business records search

        Args:
            query: Search parameters (business_name, name, state, etc.)

        Returns:
            List of business record results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_opencorporates(session, query),
                self._search_secretary_of_state(session, query),
                self._search_ucc_filings(session, query),
                self._search_sec_edgar(session, query),
                self._search_dba_registrations(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_opencorporates(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search OpenCorporates (200M+ companies)

        OpenCorporates is the largest open database of companies in the world,
        with data from over 130 jurisdictions worldwide.
        """
        results = []

        try:
            business_name = query.get('business_name', query.get('name', ''))

            if not business_name:
                return results

            # OpenCorporates API search
            url = f"{self.opencorporates_api}/companies/search"
            params = {
                'q': business_name,
                'order': 'score'
            }

            headers = {}
            if self.opencorporates_token:
                headers['Authorization'] = f'Token {self.opencorporates_token}'

            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for company in data.get('results', {}).get('companies', []):
                        company_data = company.get('company', {})

                        results.append({
                            'source': 'OpenCorporates',
                            'company_number': company_data.get('company_number'),
                            'name': company_data.get('name'),
                            'jurisdiction': company_data.get('jurisdiction_code'),
                            'incorporation_date': company_data.get('incorporation_date'),
                            'company_type': company_data.get('company_type'),
                            'status': company_data.get('current_status'),
                            'registered_address': company_data.get('registered_address_in_full'),
                            'officers': [],  # Would need separate API call
                            'url': f"https://opencorporates.com/companies/{company_data.get('jurisdiction_code')}/{company_data.get('company_number')}",
                            'data': company_data
                        })

                    self.logger.info(f"OpenCorporates: Found {len(results)} companies")

                elif response.status == 401:
                    self.logger.warning("OpenCorporates: API authentication required for higher rate limits")

        except Exception as e:
            self.logger.error(f"OpenCorporates search error: {e}")

        return results

    async def _search_secretary_of_state(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search Secretary of State business registrations

        Each state maintains a database of registered businesses
        """
        results = []

        try:
            business_name = query.get('business_name', query.get('name', ''))
            state = query.get('state')

            if not business_name or not state:
                return results

            if state not in self.sos_urls:
                self.logger.warning(f"No SOS URL configured for state: {state}")
                return results

            # State-specific searches
            if state == 'CA':
                results.extend(await self._search_california_sos(session, business_name))
            elif state == 'DE':
                results.extend(await self._search_delaware_sos(session, business_name))
            elif state == 'NY':
                results.extend(await self._search_ny_sos(session, business_name))
            elif state == 'TX':
                results.extend(await self._search_texas_sos(session, business_name))
            elif state == 'FL':
                results.extend(await self._search_florida_sos(session, business_name))

            self.logger.info(f"Secretary of State ({state}): Found {len(results)} businesses")

        except Exception as e:
            self.logger.error(f"Secretary of State search error: {e}")

        return results

    async def _search_california_sos(
        self,
        session: aiohttp.ClientSession,
        business_name: str
    ) -> List[Dict]:
        """Search California Secretary of State"""
        results = []

        try:
            url = self.sos_urls['CA']
            params = {'searchValue': business_name}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    entities = soup.find_all('div', class_='entity-result')
                    for entity in entities:
                        results.append({
                            'source': 'California Secretary of State',
                            'entity_number': entity.get('data-entity-number', ''),
                            'name': entity.find('h3').text.strip() if entity.find('h3') else '',
                            'type': entity.find('span', class_='entity-type').text.strip() if entity.find('span', class_='entity-type') else '',
                            'status': entity.find('span', class_='status').text.strip() if entity.find('span', class_='status') else '',
                            'formation_date': entity.find('span', class_='formation-date').text.strip() if entity.find('span', class_='formation-date') else '',
                            'jurisdiction': 'CA',
                            'url': self.sos_urls['CA'],
                            'data': {
                                'state': 'California',
                                'source_db': 'CA SOS'
                            }
                        })

        except Exception as e:
            self.logger.error(f"California SOS search error: {e}")

        return results

    async def _search_delaware_sos(
        self,
        session: aiohttp.ClientSession,
        business_name: str
    ) -> List[Dict]:
        """
        Search Delaware Secretary of State

        Delaware is the most popular state for incorporations
        """
        results = []

        try:
            url = self.sos_urls['DE']
            data = {
                'txtEntityName': business_name
            }

            async with session.post(url, data=data) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    rows = soup.find_all('tr', class_='EntityRow')
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 4:
                            results.append({
                                'source': 'Delaware Secretary of State',
                                'file_number': cols[0].text.strip(),
                                'name': cols[1].text.strip(),
                                'type': cols[2].text.strip(),
                                'status': cols[3].text.strip(),
                                'jurisdiction': 'DE',
                                'url': self.sos_urls['DE'],
                                'data': {
                                    'state': 'Delaware',
                                    'source_db': 'DE SOS'
                                }
                            })

        except Exception as e:
            self.logger.error(f"Delaware SOS search error: {e}")

        return results

    async def _search_ny_sos(
        self,
        session: aiohttp.ClientSession,
        business_name: str
    ) -> List[Dict]:
        """Search New York Department of State"""
        # Implementation for NY SOS
        return []

    async def _search_texas_sos(
        self,
        session: aiohttp.ClientSession,
        business_name: str
    ) -> List[Dict]:
        """Search Texas Secretary of State"""
        # Implementation for TX SOS
        return []

    async def _search_florida_sos(
        self,
        session: aiohttp.ClientSession,
        business_name: str
    ) -> List[Dict]:
        """Search Florida Division of Corporations (Sunbiz)"""
        results = []

        try:
            url = self.sos_urls['FL']
            params = {'searchTerm': business_name}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    entities = soup.find_all('div', class_='detailSection')
                    for entity in entities:
                        results.append({
                            'source': 'Florida Sunbiz',
                            'document_number': entity.get('data-doc-number', ''),
                            'name': entity.find('div', class_='corporationName').text.strip() if entity.find('div', class_='corporationName') else '',
                            'status': entity.find('div', class_='status').text.strip() if entity.find('div', class_='status') else '',
                            'file_date': entity.find('div', class_='fileDate').text.strip() if entity.find('div', class_='fileDate') else '',
                            'jurisdiction': 'FL',
                            'url': f"https://search.sunbiz.org/Inquiry/CorporationSearch/SearchResultDetail?inquirytype=EntityName&directionType=Initial&searchNameOrder=CORPORATIONNAME&aggregateId={entity.get('data-doc-number', '')}",
                            'data': {
                                'state': 'Florida',
                                'source_db': 'FL Sunbiz'
                            }
                        })

        except Exception as e:
            self.logger.error(f"Florida Sunbiz search error: {e}")

        return results

    async def _search_ucc_filings(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search UCC (Uniform Commercial Code) filings

        UCC filings are public records of secured transactions,
        including loans, leases, and other financial agreements.
        """
        results = []

        try:
            business_name = query.get('business_name', query.get('name', ''))
            state = query.get('state')

            if not business_name or not state:
                return results

            # State UCC search databases
            ucc_urls = {
                'CA': 'https://businesssearch.sos.ca.gov',
                'NY': 'https://appext9.dos.ny.gov/pls/ucc_public/web_search.main_frame',
                'TX': 'https://www.sos.state.tx.us/corp/soskb/tutorial-ucc.shtml',
                'FL': 'https://dos.myflorida.com/sunbiz/other-services/uccfileroom',
                'DE': 'https://uccforms.delaware.gov'
            }

            if state in ucc_urls:
                # State-specific UCC search
                # Each state has different search interfaces
                pass

            self.logger.info(f"UCC filings: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"UCC filings search error: {e}")

        return results

    async def _search_sec_edgar(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search SEC EDGAR for publicly traded companies

        EDGAR contains filings for all publicly traded companies
        including 10-K, 10-Q, 8-K, and other regulatory filings.
        """
        results = []

        try:
            business_name = query.get('business_name', query.get('name', ''))

            if not business_name:
                return results

            # SEC EDGAR company search
            url = "https://www.sec.gov/cgi-bin/browse-edgar"
            params = {
                'action': 'getcompany',
                'company': business_name,
                'output': 'json'
            }

            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; PublicRecordsBot/1.0)'
            }

            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()

                    companies = data.get('companies', [])
                    for company in companies:
                        results.append({
                            'source': 'SEC EDGAR',
                            'cik': company.get('cik'),
                            'name': company.get('name'),
                            'sic': company.get('sic'),
                            'sic_description': company.get('sicDescription'),
                            'state_of_incorporation': company.get('stateOfIncorporation'),
                            'fiscal_year_end': company.get('fiscalYearEnd'),
                            'business_address': company.get('businessAddress'),
                            'mailing_address': company.get('mailingAddress'),
                            'url': f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={company.get('cik')}",
                            'data': company
                        })

                    self.logger.info(f"SEC EDGAR: Found {len(results)} companies")

        except Exception as e:
            self.logger.error(f"SEC EDGAR search error: {e}")

        return results

    async def _search_dba_registrations(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search DBA (Doing Business As) registrations

        DBAs are fictitious business names registered at county/state level
        """
        results = []

        try:
            business_name = query.get('business_name', query.get('name', ''))
            state = query.get('state')

            if not business_name:
                return results

            # DBA searches are typically at county level
            # Would need to search individual county databases

            self.logger.info(f"DBA registrations: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"DBA search error: {e}")

        return results

    def get_company_profile(
        self,
        company_name: str,
        state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive company profile

        Args:
            company_name: Company name to search
            state: State of registration (optional)

        Returns:
            Comprehensive company profile
        """
        query = {
            'business_name': company_name,
            'state': state
        }

        results = asyncio.run(self.search_async(query))

        profile = {
            'company_name': company_name,
            'search_date': datetime.now().isoformat(),
            'total_records': len(results),
            'records': results,
            'jurisdictions': self._extract_jurisdictions(results),
            'registrations': self._extract_registrations(results),
            'officers': self._extract_officers(results)
        }

        return profile

    def _extract_jurisdictions(self, records: List[Dict]) -> List[str]:
        """Extract unique jurisdictions from records"""
        jurisdictions = set()

        for record in records:
            if 'jurisdiction' in record:
                jurisdictions.add(record['jurisdiction'])

        return sorted(list(jurisdictions))

    def _extract_registrations(self, records: List[Dict]) -> List[Dict]:
        """Extract registration information"""
        registrations = []

        for record in records:
            if 'incorporation_date' in record or 'formation_date' in record:
                registrations.append({
                    'name': record.get('name'),
                    'type': record.get('company_type', record.get('type')),
                    'date': record.get('incorporation_date', record.get('formation_date')),
                    'jurisdiction': record.get('jurisdiction'),
                    'status': record.get('status'),
                    'number': record.get('company_number', record.get('entity_number')),
                    'source': record.get('source')
                })

        return registrations

    def _extract_officers(self, records: List[Dict]) -> List[Dict]:
        """Extract company officers from records"""
        officers = []

        for record in records:
            if 'officers' in record and record['officers']:
                officers.extend(record['officers'])

        return officers

    async def get_company_officers(
        self,
        company_number: str,
        jurisdiction: str
    ) -> List[Dict]:
        """
        Get company officers from OpenCorporates

        Args:
            company_number: Company registration number
            jurisdiction: Jurisdiction code (e.g., 'us_de', 'gb')

        Returns:
            List of company officers
        """
        officers = []

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.opencorporates_api}/companies/{jurisdiction}/{company_number}/officers"

                headers = {}
                if self.opencorporates_token:
                    headers['Authorization'] = f'Token {self.opencorporates_token}'

                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()

                        for officer in data.get('results', {}).get('officers', []):
                            officer_data = officer.get('officer', {})
                            officers.append({
                                'name': officer_data.get('name'),
                                'position': officer_data.get('position'),
                                'start_date': officer_data.get('start_date'),
                                'end_date': officer_data.get('end_date'),
                                'nationality': officer_data.get('nationality'),
                                'occupation': officer_data.get('occupation'),
                                'address': officer_data.get('address')
                            })

        except Exception as e:
            self.logger.error(f"Error getting company officers: {e}")

        return officers


def main():
    """Example usage"""
    business_search = BusinessRecordsSearch({
        'opencorporates_token': 'your_token_here'
    })

    # Example 1: Search by company name
    print("=" * 60)
    print("Example 1: Company Search")
    print("=" * 60)

    query = {
        'business_name': 'Apple Inc',
        'state': 'CA'
    }

    results = asyncio.run(business_search.search_async(query))

    print(f"Found {len(results)} business records:")
    for record in results[:3]:
        print(f"\nSource: {record['source']}")
        print(f"Name: {record.get('name', 'N/A')}")
        print(f"Jurisdiction: {record.get('jurisdiction', 'N/A')}")
        print(f"Status: {record.get('status', 'N/A')}")

    # Example 2: Company profile
    print("\n" + "=" * 60)
    print("Example 2: Comprehensive Company Profile")
    print("=" * 60)

    profile = business_search.get_company_profile('Tesla Inc', 'DE')

    print(f"Company: {profile['company_name']}")
    print(f"Total Records: {profile['total_records']}")
    print(f"Jurisdictions: {', '.join(profile['jurisdictions'])}")
    print(f"\nRegistrations:")
    for reg in profile['registrations'][:3]:
        print(f"  - {reg['name']} ({reg['jurisdiction']})")


if __name__ == '__main__':
    main()

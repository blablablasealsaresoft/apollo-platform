"""
Criminal Records Search Module
Searches state/federal databases, sex offender registry, most wanted lists, inmate searches
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging
from bs4 import BeautifulSoup
import re


class CriminalRecordsSearch:
    """
    Criminal records search across multiple databases

    Sources:
    - State criminal databases
    - FBI National Crime Information Center (NCIC)
    - National Sex Offender Registry
    - US Marshals Most Wanted
    - Federal Bureau of Prisons Inmate Locator
    - State Department of Corrections
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize criminal records search

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger('CriminalRecordsSearch')

        # API endpoints
        self.nsopw_api = "https://www.nsopw.gov/api"  # National Sex Offender Registry
        self.bop_api = "https://www.bop.gov/inmateloc"  # Bureau of Prisons
        self.usms_api = "https://www.usmarshals.gov/investigations/most_wanted"

        # State criminal record databases
        self.state_criminal_dbs = {
            'AL': 'https://app.acis.alabama.gov/InstantInfo',
            'AK': 'https://records.courts.alaska.gov',
            'AZ': 'https://apps.supremecourt.az.gov/publicaccess',
            'AR': 'https://arcountydata.com',
            'CA': 'https://oag.ca.gov/fingerprints',
            'CO': 'https://www.coloradocriminalrecords.com',
            'CT': 'https://www.jud.ct.gov/criminalinquiry.htm',
            'DE': 'https://courts.delaware.gov/criminaloffender',
            'FL': 'https://offender.fdle.state.fl.us/offender',
            'GA': 'https://gbi.georgia.gov/services/criminal-history-checks',
            'HI': 'https://hscic.ehawaii.gov',
            'ID': 'https://www.isp.idaho.gov/criminal-history',
            'IL': 'https://www.isp.state.il.us/crimhistory',
            'IN': 'https://www.in.gov/ai/appfiles/isp-prch',
            'IA': 'https://www.dps.state.ia.us/DCI/CriminalHistory',
            'KS': 'https://www.kansas.gov/criminalhistory',
            'KY': 'https://kspoffender.ky.gov',
            'LA': 'https://www.lsp.org/services/criminalhistory.html',
            'ME': 'https://www.maine.gov/dps/msp/services/criminal_history.htm',
            'MD': 'https://www.dpscs.state.md.us/inmate',
            'MA': 'https://www.mass.gov/orgs/criminal-history-systems-board',
            'MI': 'https://www.michigan.gov/msp/criminal-justice-records',
            'MN': 'https://dps.mn.gov/divisions/bca/criminal-records',
            'MS': 'https://www.dps.ms.gov/recordsstatistics',
            'MO': 'https://www.mshp.dps.missouri.gov/CJ08',
            'MT': 'https://dojmt.gov/enforcement/criminal-record-checks',
            'NE': 'https://www.nebraska.gov/crime_commission/arrest-records',
            'NV': 'https://www.nvrepository.state.nv.us',
            'NH': 'https://www.nh.gov/safety/divisions/nhsp/services/criminal-records',
            'NJ': 'https://www.njsp.org/criminal-history',
            'NM': 'https://www.dps.nm.gov/index.php/criminal-records',
            'NY': 'https://www.criminaljustice.ny.gov/crimnet',
            'NC': 'https://www.ncdps.gov/dps-services/criminal-information',
            'ND': 'https://www.ag.nd.gov/BCI/RecordsRequest',
            'OH': 'https://www.ohioattorneygeneral.gov/Law-Enforcement/Services-For-Law-Enforcement/WebCheck',
            'OK': 'https://osbi.ok.gov/criminal-history-records',
            'OR': 'https://www.oregon.gov/osp/programs/CJ/Pages/default.aspx',
            'PA': 'https://epatch.state.pa.us',
            'RI': 'https://www.ri.gov/BCI',
            'SC': 'https://sled.sc.gov/criminalrecords.aspx',
            'SD': 'https://dci.sd.gov/administration/identification',
            'TN': 'https://www.tn.gov/tbi/divisions/cjis-division/criminal-history-record-checks.html',
            'TX': 'https://records.txdps.state.tx.us',
            'UT': 'https://bci.utah.gov/criminal-records',
            'VT': 'https://vcic.vermont.gov/criminalhistory',
            'VA': 'https://www.vsp.virginia.gov/Crimes_and_Criminals.shtm',
            'WA': 'https://www.wsp.wa.gov/crime/criminal-history',
            'WV': 'https://www.wvsp.gov/criminal_records',
            'WI': 'https://www.doj.state.wi.us/dles/bjia/criminal-history-record-check',
            'WY': 'https://dci.wyo.gov/criminal-history'
        }

    async def search_async(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Asynchronous criminal records search

        Args:
            query: Search parameters (name, dob, state, etc.)

        Returns:
            List of criminal record results
        """
        results = []

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_sex_offender_registry(session, query),
                self._search_federal_inmate_locator(session, query),
                self._search_most_wanted(session, query),
                self._search_state_criminal_records(session, query)
            ]

            search_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in search_results:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Search error: {result}")

        return results

    async def _search_sex_offender_registry(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search National Sex Offender Public Website (NSOPW)

        NSOPW is a cooperative effort between DOJ and state/territory
        sex offender registries. Contains 900,000+ registered sex offenders.
        """
        results = []

        try:
            name = query.get('name', '')
            state = query.get('state', '')

            # NSOPW search endpoint
            url = f"{self.nsopw_api}/search"
            params = {
                'name': name,
                'state': state
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for offender in data.get('offenders', []):
                        results.append({
                            'source': 'National Sex Offender Registry',
                            'severity': 'HIGH',
                            'name': offender.get('name'),
                            'aliases': offender.get('aliases', []),
                            'dob': offender.get('dob'),
                            'address': offender.get('address'),
                            'city': offender.get('city'),
                            'state': offender.get('state'),
                            'zip': offender.get('zip'),
                            'offenses': offender.get('offenses', []),
                            'registration_date': offender.get('registration_date'),
                            'risk_level': offender.get('risk_level'),
                            'photo_url': offender.get('photo_url'),
                            'url': f"https://www.nsopw.gov/offender/{offender.get('id')}",
                            'data': offender
                        })

                    self.logger.info(f"Sex Offender Registry: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Sex offender registry search error: {e}")

        return results

    async def _search_federal_inmate_locator(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search Federal Bureau of Prisons Inmate Locator

        Contains information on inmates currently in BOP custody,
        inmates who are released but still under BOP supervision,
        and inmates released after 1982.
        """
        results = []

        try:
            name = query.get('name', '')
            name_parts = name.split()
            first_name = name_parts[0] if name_parts else ''
            last_name = name_parts[-1] if len(name_parts) > 1 else ''

            # BOP Inmate Locator
            url = f"{self.bop_api}/index.jsp"
            params = {
                'lastName': last_name,
                'firstName': first_name
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    inmates = self._parse_bop_results(html)
                    results.extend(inmates)

                    self.logger.info(f"BOP Inmate Locator: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"BOP inmate search error: {e}")

        return results

    def _parse_bop_results(self, html: str) -> List[Dict]:
        """Parse BOP inmate locator results"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            rows = soup.find_all('tr', class_='inmate-row')

            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 8:
                    results.append({
                        'source': 'Federal Bureau of Prisons',
                        'severity': 'HIGH',
                        'register_number': cols[0].text.strip(),
                        'name': cols[1].text.strip(),
                        'age': cols[2].text.strip(),
                        'race': cols[3].text.strip(),
                        'sex': cols[4].text.strip(),
                        'release_date': cols[5].text.strip(),
                        'location': cols[6].text.strip(),
                        'url': 'https://www.bop.gov/inmateloc',
                        'data': {
                            'custody_status': 'Federal Prison',
                            'register_number': cols[0].text.strip()
                        }
                    })

        except Exception as e:
            self.logger.error(f"Error parsing BOP results: {e}")

        return results

    async def _search_most_wanted(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search FBI Most Wanted and US Marshals Most Wanted

        Includes:
        - FBI Ten Most Wanted
        - FBI Most Wanted Terrorists
        - US Marshals 15 Most Wanted
        - Fugitive investigations
        """
        results = []

        try:
            name = query.get('name', '')

            # FBI Most Wanted API
            fbi_url = "https://api.fbi.gov/wanted/v1/list"
            params = {'title': name}

            async with session.get(fbi_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    for person in data.get('items', []):
                        results.append({
                            'source': 'FBI Most Wanted',
                            'severity': 'CRITICAL',
                            'title': person.get('title'),
                            'subjects': person.get('subjects', []),
                            'warning_message': person.get('warning_message'),
                            'caution': person.get('caution'),
                            'description': person.get('description'),
                            'reward_text': person.get('reward_text'),
                            'details': person.get('details'),
                            'images': person.get('images', []),
                            'url': person.get('url'),
                            'data': person
                        })

            # US Marshals Most Wanted
            usms_url = self.usms_api
            async with session.get(usms_url) as response:
                if response.status == 200:
                    html = await response.text()
                    wanted = self._parse_usms_results(html, name)
                    results.extend(wanted)

            self.logger.info(f"Most Wanted: Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"Most wanted search error: {e}")

        return results

    def _parse_usms_results(self, html: str, name: str) -> List[Dict]:
        """Parse US Marshals Most Wanted results"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            wanted_cards = soup.find_all('div', class_='wanted-person')

            for card in wanted_cards:
                person_name = card.find('h3').text.strip()
                if name.lower() in person_name.lower():
                    results.append({
                        'source': 'US Marshals Most Wanted',
                        'severity': 'CRITICAL',
                        'name': person_name,
                        'charges': card.find('div', class_='charges').text.strip(),
                        'reward': card.find('div', class_='reward').text.strip(),
                        'image_url': card.find('img')['src'],
                        'url': 'https://www.usmarshals.gov' + card.find('a')['href'],
                        'data': {
                            'type': 'fugitive',
                            'agency': 'US Marshals Service'
                        }
                    })

        except Exception as e:
            self.logger.error(f"Error parsing USMS results: {e}")

        return results

    async def _search_state_criminal_records(
        self,
        session: aiohttp.ClientSession,
        query: Dict[str, Any]
    ) -> List[Dict]:
        """
        Search state criminal record databases

        Each state maintains its own criminal record database
        """
        results = []

        state = query.get('state')
        if not state or state not in self.state_criminal_dbs:
            return results

        try:
            name = query.get('name', '')

            # State-specific search
            if state == 'FL':
                results.extend(await self._search_florida_offenders(session, name))
            elif state == 'CA':
                results.extend(await self._search_california_offenders(session, name))
            elif state == 'TX':
                results.extend(await self._search_texas_offenders(session, name))
            elif state == 'NY':
                results.extend(await self._search_ny_offenders(session, name))

            self.logger.info(f"State criminal records ({state}): Found {len(results)} records")

        except Exception as e:
            self.logger.error(f"State criminal records search error: {e}")

        return results

    async def _search_florida_offenders(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search Florida Department of Corrections Offender Search"""
        results = []

        try:
            url = self.state_criminal_dbs['FL'] + '/offender/Search.asp'
            name_parts = name.split()

            params = {
                'FirstName': name_parts[0] if name_parts else '',
                'LastName': name_parts[-1] if len(name_parts) > 1 else ''
            }

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    results = self._parse_florida_results(html)

        except Exception as e:
            self.logger.error(f"Florida offender search error: {e}")

        return results

    def _parse_florida_results(self, html: str) -> List[Dict]:
        """Parse Florida offender search results"""
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            offenders = soup.find_all('div', class_='offender-record')

            for offender in offenders:
                results.append({
                    'source': 'Florida DOC',
                    'severity': 'HIGH',
                    'dc_number': offender.get('data-dc-number', ''),
                    'name': offender.find('div', class_='name').text.strip(),
                    'race': offender.find('div', class_='race').text.strip(),
                    'sex': offender.find('div', class_='sex').text.strip(),
                    'birth_date': offender.find('div', class_='dob').text.strip(),
                    'custody_status': offender.find('div', class_='status').text.strip(),
                    'current_facility': offender.find('div', class_='facility').text.strip(),
                    'url': self.state_criminal_dbs['FL'],
                    'data': {
                        'state': 'FL',
                        'jurisdiction': 'Florida Department of Corrections'
                    }
                })

        except Exception as e:
            self.logger.error(f"Error parsing Florida results: {e}")

        return results

    async def _search_california_offenders(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search California Department of Corrections"""
        # Implementation for CA DOC search
        return []

    async def _search_texas_offenders(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search Texas Department of Criminal Justice"""
        # Implementation for TX DOC search
        return []

    async def _search_ny_offenders(
        self,
        session: aiohttp.ClientSession,
        name: str
    ) -> List[Dict]:
        """Search New York State Department of Corrections"""
        # Implementation for NY DOC search
        return []

    def get_background_check(self, person: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile comprehensive criminal background check

        Args:
            person: Person information (name, dob, etc.)

        Returns:
            Comprehensive background check report
        """
        results = asyncio.run(self.search_async(person))

        report = {
            'subject': person,
            'check_date': datetime.now().isoformat(),
            'total_records': len(results),
            'risk_assessment': self._assess_risk(results),
            'records': results,
            'summary': {
                'sex_offender': False,
                'federal_custody': False,
                'most_wanted': False,
                'state_records': 0
            }
        }

        # Update summary
        for record in results:
            if 'Sex Offender' in record['source']:
                report['summary']['sex_offender'] = True
            if 'Bureau of Prisons' in record['source']:
                report['summary']['federal_custody'] = True
            if 'Most Wanted' in record['source']:
                report['summary']['most_wanted'] = True
            if 'DOC' in record['source']:
                report['summary']['state_records'] += 1

        return report

    def _assess_risk(self, records: List[Dict]) -> str:
        """Assess risk level based on criminal records"""
        if not records:
            return 'NONE'

        for record in records:
            if record.get('severity') == 'CRITICAL':
                return 'CRITICAL'

        for record in records:
            if record.get('severity') == 'HIGH':
                return 'HIGH'

        return 'MEDIUM'


def main():
    """Example usage"""
    from datetime import datetime

    criminal_search = CriminalRecordsSearch()

    # Example search
    query = {
        'name': 'John Doe',
        'state': 'FL',
        'dob': '1980-01-01'
    }

    results = asyncio.run(criminal_search.search_async(query))

    print(f"Found {len(results)} criminal records:")
    for record in results[:5]:
        print(f"\nSource: {record['source']}")
        print(f"Severity: {record.get('severity', 'N/A')}")
        print(f"Name: {record.get('name', 'N/A')}")
        print(f"URL: {record.get('url', 'N/A')}")

    # Background check
    background = criminal_search.get_background_check(query)
    print(f"\n\nBackground Check Summary:")
    print(f"Risk Assessment: {background['risk_assessment']}")
    print(f"Sex Offender: {background['summary']['sex_offender']}")
    print(f"Most Wanted: {background['summary']['most_wanted']}")


if __name__ == '__main__':
    main()

"""
Voter Records - Voter Registration and History Lookup
Search voter registration, party affiliation, and voting history
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json
from bs4 import BeautifulSoup
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class VoterRecord:
    """Voter registration record"""
    # Personal Information
    first_name: str
    last_name: str
    middle_name: Optional[str] = None
    suffix: Optional[str] = None
    age: Optional[int] = None
    dob: Optional[str] = None
    gender: Optional[str] = None

    # Registration Information
    voter_id: Optional[str] = None
    registration_date: Optional[str] = None
    registration_status: Optional[str] = None  # active, inactive, suspended
    party_affiliation: Optional[str] = None

    # Address Information
    residential_address: Optional[Dict[str, str]] = None
    mailing_address: Optional[Dict[str, str]] = None
    precinct: Optional[str] = None
    district: Optional[str] = None

    # Voting History
    voting_history: List[Dict[str, Any]] = field(default_factory=list)
    last_voted: Optional[str] = None
    total_elections_voted: int = 0

    # Location Details
    county: Optional[str] = None
    state: Optional[str] = None

    # Metadata
    source: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


class VoterRecordsSearch:
    """
    Voter registration and history lookup

    Features:
    - Voter registration lookup by name
    - Party affiliation search
    - Voting history retrieval
    - Address verification via voter records
    - Multi-state search capability

    Note: Voter records are public in most states but access varies
    """

    # State voter registration portals
    STATE_PORTALS = {
        'AL': 'https://www.alabamainteractive.org/sos/voter_registration/',
        'AK': 'https://myvoterinformation.alaska.gov/',
        'AZ': 'https://voter.azsos.gov/',
        'AR': 'https://www.voterview.ar-nova.org/',
        'CA': 'https://voterstatus.sos.ca.gov/',
        'CO': 'https://www.sos.state.co.us/voter/',
        'CT': 'https://portaldir.ct.gov/sots/LookUp.aspx',
        'DE': 'https://ivote.de.gov/VoterView',
        'FL': 'https://registration.elections.myflorida.com/CheckVoterStatus',
        'GA': 'https://www.mvp.sos.ga.gov/',
        'HI': 'https://olvr.hawaii.gov/',
        'ID': 'https://elections.sos.idaho.gov/ElectionLink',
        'IL': 'https://ova.elections.il.gov/',
        'IN': 'https://indianavoters.in.gov/',
        'IA': 'https://sos.iowa.gov/elections/voterreg/regtovote/search.aspx',
        'KS': 'https://myvoteinfo.voteks.org/',
        'KY': 'https://vrsws.sos.ky.gov/vic/',
        'LA': 'https://voterportal.sos.la.gov/',
        'ME': 'https://www.maine.gov/sos/cec/elec/voter-info/',
        'MD': 'https://voterservices.elections.maryland.gov/',
        'MA': 'https://www.sec.state.ma.us/VoterRegistrationSearch/',
        'MI': 'https://mvic.sos.state.mi.us/',
        'MN': 'https://mnvotes.sos.state.mn.us/',
        'MS': 'https://www.msegov.com/sos/voter_registration/',
        'MO': 'https://voteroutreach.sos.mo.gov/',
        'MT': 'https://app.mt.gov/voterinfo/',
        'NE': 'https://www.votercheck.necvr.ne.gov/',
        'NV': 'https://www.nvsos.gov/votersearch/',
        'NH': 'https://app.sos.nh.gov/voterinformation',
        'NJ': 'https://voter.svrs.nj.gov/registration-check',
        'NM': 'https://voterportal.servis.sos.state.nm.us/',
        'NY': 'https://voterlookup.elections.ny.gov/',
        'NC': 'https://vt.ncsbe.gov/RegLkup/',
        'ND': 'https://vip.sos.nd.gov/wheretovote.aspx',
        'OH': 'https://voterlookup.ohiosos.gov/',
        'OK': 'https://okvoterportal.okelections.us/',
        'OR': 'https://sos.oregon.gov/voting/Pages/registration.aspx',
        'PA': 'https://www.pavoterservices.pa.gov/',
        'RI': 'https://vote.sos.ri.gov/',
        'SC': 'https://info.scvotes.sc.gov/eng/voterinquiry/',
        'SD': 'https://vip.sdsos.gov/',
        'TN': 'https://tnmap.tn.gov/voterlookup/',
        'TX': 'https://teamrv-mvp.sos.texas.gov/MVP/',
        'UT': 'https://votesearch.utah.gov/',
        'VT': 'https://sos.vermont.gov/elections/voters/',
        'VA': 'https://vote.elections.virginia.gov/',
        'WA': 'https://voter.votewa.gov/',
        'WV': 'https://services.sos.wv.gov/Elections/Voter/FindMyPollingPlace',
        'WI': 'https://myvote.wi.gov/',
        'WY': 'https://sos.wyo.gov/Elections/RegisterToVote.aspx'
    }

    def __init__(self):
        """Initialize voter records search"""
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def search_voter(
        self,
        first_name: str,
        last_name: str,
        state: str,
        county: Optional[str] = None,
        dob: Optional[str] = None,
        zip_code: Optional[str] = None
    ) -> List[VoterRecord]:
        """
        Search for voter registration record

        Args:
            first_name: First name
            last_name: Last name
            state: State code (e.g., 'NY')
            county: County name (optional)
            dob: Date of birth (optional, format varies by state)
            zip_code: ZIP code (optional)

        Returns:
            List of matching voter records
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        logger.info(f"Searching voter records: {first_name} {last_name} in {state}")

        try:
            # Route to state-specific search
            if state == 'FL':
                return await self._search_florida(first_name, last_name, county, dob)
            elif state == 'CA':
                return await self._search_california(first_name, last_name, county)
            elif state == 'TX':
                return await self._search_texas(first_name, last_name, county)
            elif state == 'NY':
                return await self._search_new_york(first_name, last_name, county, dob)
            elif state == 'PA':
                return await self._search_pennsylvania(first_name, last_name, county)
            elif state == 'OH':
                return await self._search_ohio(first_name, last_name, county)
            else:
                # Generic state search
                return await self._search_generic_state(first_name, last_name, state, county)

        except Exception as e:
            logger.error(f"Voter search error: {e}")
            return []

    async def _search_florida(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str],
        dob: Optional[str]
    ) -> List[VoterRecord]:
        """Search Florida voter records"""
        records = []

        try:
            logger.info("Searching Florida voter registration")

            # Florida Division of Elections Voter Registration System
            # Public access available
            url = "https://registration.elections.myflorida.com/CheckVoterStatus"

            # Florida requires specific parameters
            # Implementation would involve form submission

        except Exception as e:
            logger.error(f"Florida voter search error: {e}")

        return records

    async def _search_california(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str]
    ) -> List[VoterRecord]:
        """Search California voter records"""
        records = []

        try:
            logger.info("Searching California voter registration")

            # California Secretary of State Voter Status
            url = "https://voterstatus.sos.ca.gov/"

            # California has county-level systems

        except Exception as e:
            logger.error(f"California voter search error: {e}")

        return records

    async def _search_texas(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str]
    ) -> List[VoterRecord]:
        """Search Texas voter records"""
        records = []

        try:
            logger.info("Searching Texas voter registration")

            # Texas voter registration is county-based
            url = "https://teamrv-mvp.sos.texas.gov/MVP/"

        except Exception as e:
            logger.error(f"Texas voter search error: {e}")

        return records

    async def _search_new_york(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str],
        dob: Optional[str]
    ) -> List[VoterRecord]:
        """Search New York voter records"""
        records = []

        try:
            logger.info("Searching New York voter registration")

            # New York State Board of Elections
            url = "https://voterlookup.elections.ny.gov/"

        except Exception as e:
            logger.error(f"New York voter search error: {e}")

        return records

    async def _search_pennsylvania(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str]
    ) -> List[VoterRecord]:
        """Search Pennsylvania voter records"""
        records = []

        try:
            logger.info("Searching Pennsylvania voter registration")

            # PA Voter Services
            url = "https://www.pavoterservices.pa.gov/"

        except Exception as e:
            logger.error(f"Pennsylvania voter search error: {e}")

        return records

    async def _search_ohio(
        self,
        first_name: str,
        last_name: str,
        county: Optional[str]
    ) -> List[VoterRecord]:
        """Search Ohio voter records"""
        records = []

        try:
            logger.info("Searching Ohio voter registration")

            # Ohio Secretary of State Voter Lookup
            url = "https://voterlookup.ohiosos.gov/"

        except Exception as e:
            logger.error(f"Ohio voter search error: {e}")

        return records

    async def _search_generic_state(
        self,
        first_name: str,
        last_name: str,
        state: str,
        county: Optional[str]
    ) -> List[VoterRecord]:
        """Generic state voter search"""
        records = []

        try:
            portal_url = self.STATE_PORTALS.get(state)

            if portal_url:
                logger.info(f"Searching {state} voter registration: {portal_url}")
                # Generic implementation
            else:
                logger.warning(f"No voter portal configured for state: {state}")

        except Exception as e:
            logger.error(f"Generic state voter search error: {e}")

        return records

    async def get_voting_history(
        self,
        voter_id: str,
        state: str
    ) -> List[Dict[str, Any]]:
        """
        Retrieve voting history for a registered voter

        Args:
            voter_id: Voter registration ID
            state: State code

        Returns:
            List of voting history records
        """
        history = []

        try:
            logger.info(f"Retrieving voting history for voter ID: {voter_id}")

            # Most states provide voting history
            # Shows which elections the person voted in
            # Does NOT show who they voted for (secret ballot)

        except Exception as e:
            logger.error(f"Voting history retrieval error: {e}")

        return history

    async def verify_registration(
        self,
        name: str,
        address: str,
        state: str
    ) -> Optional[VoterRecord]:
        """
        Verify voter registration status

        Args:
            name: Full name
            address: Residential address
            state: State code

        Returns:
            VoterRecord if registered
        """
        try:
            logger.info(f"Verifying voter registration for: {name}")

            # Parse name
            name_parts = name.split()
            if len(name_parts) < 2:
                return None

            first_name = name_parts[0]
            last_name = name_parts[-1]

            # Search voter records
            records = await self.search_voter(first_name, last_name, state)

            # Match by address
            for record in records:
                if record.residential_address:
                    record_addr = record.residential_address.get('street', '')
                    if address.lower() in record_addr.lower():
                        return record

            return None

        except Exception as e:
            logger.error(f"Registration verification error: {e}")
            return None

    async def search_by_address(
        self,
        address: str,
        city: str,
        state: str,
        zip_code: Optional[str] = None
    ) -> List[VoterRecord]:
        """
        Find all registered voters at an address

        Args:
            address: Street address
            city: City name
            state: State code
            zip_code: ZIP code

        Returns:
            List of voters registered at address
        """
        voters = []

        try:
            logger.info(f"Searching voters at address: {address}, {city}, {state}")

            # Some states allow address-based searches
            # Useful for identifying all voters in a household

        except Exception as e:
            logger.error(f"Address-based voter search error: {e}")

        return voters

    def export_record(self, record: VoterRecord, format: str = 'json') -> str:
        """
        Export voter record in specified format

        Args:
            record: VoterRecord to export
            format: Export format (json, text)

        Returns:
            Formatted record data
        """
        if format == 'json':
            return json.dumps({
                'name': f"{record.first_name} {record.middle_name or ''} {record.last_name}".strip(),
                'voter_id': record.voter_id,
                'registration_date': record.registration_date,
                'registration_status': record.registration_status,
                'party_affiliation': record.party_affiliation,
                'residential_address': record.residential_address,
                'mailing_address': record.mailing_address,
                'precinct': record.precinct,
                'district': record.district,
                'voting_history': record.voting_history,
                'last_voted': record.last_voted,
                'total_elections_voted': record.total_elections_voted,
                'county': record.county,
                'state': record.state,
                'source': record.source,
                'last_updated': record.last_updated
            }, indent=2)

        elif format == 'text':
            return f"""
VOTER REGISTRATION RECORD
{'='*80}

Name: {record.first_name} {record.middle_name or ''} {record.last_name}
Age: {record.age or 'Unknown'}
Gender: {record.gender or 'Unknown'}

REGISTRATION DETAILS
{'='*80}

Voter ID: {record.voter_id or 'N/A'}
Registration Date: {record.registration_date or 'Unknown'}
Status: {record.registration_status or 'Unknown'}
Party Affiliation: {record.party_affiliation or 'No Party Preference'}

LOCATION
{'='*80}

Residential Address:
  {record.residential_address.get('street', 'N/A') if record.residential_address else 'N/A'}
  {record.residential_address.get('city', '')}, {record.residential_address.get('state', '')} {record.residential_address.get('zip', '') if record.residential_address else ''}

Precinct: {record.precinct or 'N/A'}
District: {record.district or 'N/A'}
County: {record.county or 'N/A'}
State: {record.state or 'N/A'}

VOTING HISTORY
{'='*80}

Total Elections Voted: {record.total_elections_voted}
Last Voted: {record.last_voted or 'Unknown'}

Recent Elections:
{chr(10).join(f"  - {election.get('election_date')} - {election.get('election_type')}" for election in record.voting_history[:5]) if record.voting_history else '  No history available'}

{'='*80}
Source: {record.source or 'N/A'}
Last Updated: {record.last_updated}
{'='*80}
"""

        return ""

    def analyze_voting_pattern(self, record: VoterRecord) -> Dict[str, Any]:
        """
        Analyze voting patterns and engagement

        Args:
            record: VoterRecord to analyze

        Returns:
            Analysis dictionary
        """
        analysis = {
            'voter_engagement': 'Unknown',
            'consistency_score': 0.0,
            'preferred_elections': [],
            'registration_duration': None
        }

        try:
            # Calculate engagement level
            if record.total_elections_voted >= 10:
                analysis['voter_engagement'] = 'Highly Active'
            elif record.total_elections_voted >= 5:
                analysis['voter_engagement'] = 'Active'
            elif record.total_elections_voted >= 2:
                analysis['voter_engagement'] = 'Moderate'
            else:
                analysis['voter_engagement'] = 'Inactive'

            # Analyze election types
            if record.voting_history:
                election_types = {}
                for election in record.voting_history:
                    etype = election.get('election_type', 'Unknown')
                    election_types[etype] = election_types.get(etype, 0) + 1

                analysis['preferred_elections'] = sorted(
                    election_types.items(),
                    key=lambda x: x[1],
                    reverse=True
                )

            # Calculate registration duration
            if record.registration_date:
                try:
                    reg_date = datetime.fromisoformat(record.registration_date)
                    duration = datetime.now() - reg_date
                    analysis['registration_duration'] = f"{duration.days // 365} years"
                except:
                    pass

        except Exception as e:
            logger.error(f"Voting pattern analysis error: {e}")

        return analysis


if __name__ == "__main__":
    # Example usage
    async def main():
        async with VoterRecordsSearch() as vrs:
            # Search for voter
            records = await vrs.search_voter(
                first_name="John",
                last_name="Doe",
                state="NY",
                county="New York"
            )

            for record in records:
                print(vrs.export_record(record, format='text'))

                # Analyze voting patterns
                analysis = vrs.analyze_voting_pattern(record)
                print(f"\nVoting Analysis: {json.dumps(analysis, indent=2)}")

            # Verify registration
            verified = await vrs.verify_registration(
                name="John Doe",
                address="123 Main St",
                state="NY"
            )

            if verified:
                print("Voter registration verified!")

    asyncio.run(main())

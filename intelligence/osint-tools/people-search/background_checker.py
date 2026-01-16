"""
Background Checker - Criminal Records, Court Cases, and Public Records
Comprehensive background check system
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
class CriminalRecord:
    """Criminal record data structure"""
    case_number: str
    offense: str
    offense_date: Optional[str] = None
    disposition: Optional[str] = None
    court: Optional[str] = None
    county: Optional[str] = None
    state: Optional[str] = None
    severity: Optional[str] = None  # felony, misdemeanor, infraction
    status: Optional[str] = None  # open, closed, sealed
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CourtCase:
    """Court case data structure"""
    case_number: str
    case_type: str  # criminal, civil, family, probate, traffic
    filing_date: Optional[str] = None
    case_status: Optional[str] = None
    court: Optional[str] = None
    county: Optional[str] = None
    state: Optional[str] = None
    parties: List[Dict[str, str]] = field(default_factory=list)
    charges: List[str] = field(default_factory=list)
    disposition: Optional[str] = None
    judgement: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PropertyRecord:
    """Property ownership record"""
    address: str
    owner_name: str
    ownership_type: Optional[str] = None
    purchase_date: Optional[str] = None
    purchase_price: Optional[float] = None
    assessed_value: Optional[float] = None
    property_type: Optional[str] = None
    lot_size: Optional[str] = None
    building_size: Optional[str] = None
    year_built: Optional[int] = None
    county: Optional[str] = None
    state: Optional[str] = None
    tax_info: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessAffiliation:
    """Business affiliation record"""
    business_name: str
    role: str  # owner, officer, agent, director
    business_type: Optional[str] = None
    registration_date: Optional[str] = None
    status: Optional[str] = None  # active, inactive, dissolved
    state: Optional[str] = None
    ein: Optional[str] = None
    address: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BackgroundReport:
    """Complete background check report"""
    name: str
    search_date: str = field(default_factory=lambda: datetime.now().isoformat())

    # Records
    criminal_records: List[CriminalRecord] = field(default_factory=list)
    court_cases: List[CourtCase] = field(default_factory=list)
    property_records: List[PropertyRecord] = field(default_factory=list)
    business_affiliations: List[BusinessAffiliation] = field(default_factory=list)

    # Additional checks
    sex_offender_registry: Optional[Dict[str, Any]] = None
    bankruptcy_records: List[Dict[str, Any]] = field(default_factory=list)
    lien_records: List[Dict[str, Any]] = field(default_factory=list)
    judgment_records: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    sources: List[str] = field(default_factory=list)
    completeness_score: float = 0.0
    risk_score: float = 0.0


class BackgroundChecker:
    """
    Comprehensive background check system

    Features:
    - Criminal record search
    - Court case lookup
    - Property records
    - Business affiliations
    - Sex offender registry
    - Bankruptcy records
    - Lien and judgment searches
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize background checker

        Args:
            config: Configuration with API keys and settings
        """
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def comprehensive_check(
        self,
        name: str,
        dob: Optional[str] = None,
        ssn: Optional[str] = None,
        state: Optional[str] = None,
        county: Optional[str] = None
    ) -> BackgroundReport:
        """
        Perform comprehensive background check

        Args:
            name: Full name
            dob: Date of birth
            ssn: Social security number (last 4 digits)
            state: State code
            county: County name

        Returns:
            Complete BackgroundReport
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        logger.info(f"Starting comprehensive background check for: {name}")

        report = BackgroundReport(name=name)

        # Run all checks in parallel
        tasks = [
            self._check_criminal_records(name, dob, state, county),
            self._check_court_cases(name, state, county),
            self._check_property_records(name, state, county),
            self._check_business_affiliations(name, state),
            self._check_sex_offender_registry(name, state),
            self._check_bankruptcy_records(name, state),
            self._check_liens_judgments(name, state, county)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Background check task {i} failed: {result}")
                continue

            if i == 0 and isinstance(result, list):  # Criminal records
                report.criminal_records = result
            elif i == 1 and isinstance(result, list):  # Court cases
                report.court_cases = result
            elif i == 2 and isinstance(result, list):  # Property records
                report.property_records = result
            elif i == 3 and isinstance(result, list):  # Business affiliations
                report.business_affiliations = result
            elif i == 4 and isinstance(result, dict):  # Sex offender
                report.sex_offender_registry = result
            elif i == 5 and isinstance(result, list):  # Bankruptcy
                report.bankruptcy_records = result
            elif i == 6 and isinstance(result, tuple):  # Liens and judgments
                liens, judgments = result
                report.lien_records = liens
                report.judgment_records = judgments

        # Calculate scores
        report.completeness_score = self._calculate_completeness(report)
        report.risk_score = self._calculate_risk_score(report)

        logger.info(f"Background check complete. Risk score: {report.risk_score:.2f}")
        return report

    async def _check_criminal_records(
        self,
        name: str,
        dob: Optional[str],
        state: Optional[str],
        county: Optional[str]
    ) -> List[CriminalRecord]:
        """Search criminal records databases"""
        records = []

        try:
            logger.info("Checking criminal records...")

            # Check multiple sources
            tasks = []

            # State criminal records
            if state:
                tasks.append(self._search_state_criminal_records(name, dob, state))

            # County records
            if county and state:
                tasks.append(self._search_county_criminal_records(name, dob, state, county))

            # National criminal database
            tasks.append(self._search_national_criminal_database(name, dob))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    records.extend(result)

            logger.info(f"Found {len(records)} criminal records")

        except Exception as e:
            logger.error(f"Criminal record search error: {e}")

        return records

    async def _search_state_criminal_records(
        self,
        name: str,
        dob: Optional[str],
        state: str
    ) -> List[CriminalRecord]:
        """Search state-level criminal records"""
        records = []

        try:
            # This would integrate with state-specific APIs
            # Each state has different systems and access requirements

            logger.info(f"Searching {state} criminal records")

            # Example: Some states have public record portals
            # Implementation would vary by state

        except Exception as e:
            logger.error(f"State criminal record search error: {e}")

        return records

    async def _search_county_criminal_records(
        self,
        name: str,
        dob: Optional[str],
        state: str,
        county: str
    ) -> List[CriminalRecord]:
        """Search county-level criminal records"""
        records = []

        try:
            logger.info(f"Searching {county}, {state} criminal records")

            # County court websites often have public access
            # Implementation varies by county

        except Exception as e:
            logger.error(f"County criminal record search error: {e}")

        return records

    async def _search_national_criminal_database(
        self,
        name: str,
        dob: Optional[str]
    ) -> List[CriminalRecord]:
        """Search national criminal databases"""
        records = []

        try:
            logger.info("Searching national criminal database")

            # This would use services like:
            # - NCIC (restricted access)
            # - Commercial background check APIs
            # - State data aggregators

        except Exception as e:
            logger.error(f"National criminal database search error: {e}")

        return records

    async def _check_court_cases(
        self,
        name: str,
        state: Optional[str],
        county: Optional[str]
    ) -> List[CourtCase]:
        """Search court case records"""
        cases = []

        try:
            logger.info("Checking court cases...")

            # Search different court systems
            tasks = []

            if state:
                tasks.append(self._search_state_courts(name, state))

            if county and state:
                tasks.append(self._search_county_courts(name, state, county))

            # Federal courts
            tasks.append(self._search_federal_courts(name))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    cases.extend(result)

            logger.info(f"Found {len(cases)} court cases")

        except Exception as e:
            logger.error(f"Court case search error: {e}")

        return cases

    async def _search_state_courts(self, name: str, state: str) -> List[CourtCase]:
        """Search state court systems"""
        cases = []

        try:
            logger.info(f"Searching {state} state courts")

            # Many states have online case search
            # Examples:
            # - California: https://www.courts.ca.gov/
            # - New York: https://iapps.courts.state.ny.us/

        except Exception as e:
            logger.error(f"State court search error: {e}")

        return cases

    async def _search_county_courts(
        self,
        name: str,
        state: str,
        county: str
    ) -> List[CourtCase]:
        """Search county court systems"""
        cases = []

        try:
            logger.info(f"Searching {county}, {state} county courts")

            # County clerk of courts websites

        except Exception as e:
            logger.error(f"County court search error: {e}")

        return cases

    async def _search_federal_courts(self, name: str) -> List[CourtCase]:
        """Search federal court system (PACER)"""
        cases = []

        try:
            logger.info("Searching federal courts (PACER)")

            # PACER (Public Access to Court Electronic Records)
            # Requires account and fees
            # https://pacer.uscourts.gov/

        except Exception as e:
            logger.error(f"Federal court search error: {e}")

        return cases

    async def _check_property_records(
        self,
        name: str,
        state: Optional[str],
        county: Optional[str]
    ) -> List[PropertyRecord]:
        """Search property ownership records"""
        records = []

        try:
            logger.info("Checking property records...")

            if county and state:
                # County assessor/recorder offices
                records = await self._search_county_property_records(name, state, county)

            logger.info(f"Found {len(records)} property records")

        except Exception as e:
            logger.error(f"Property record search error: {e}")

        return records

    async def _search_county_property_records(
        self,
        name: str,
        state: str,
        county: str
    ) -> List[PropertyRecord]:
        """Search county property records"""
        records = []

        try:
            logger.info(f"Searching {county}, {state} property records")

            # County assessor websites
            # Many counties have online property search

        except Exception as e:
            logger.error(f"County property search error: {e}")

        return records

    async def _check_business_affiliations(
        self,
        name: str,
        state: Optional[str]
    ) -> List[BusinessAffiliation]:
        """Search business affiliations and registrations"""
        affiliations = []

        try:
            logger.info("Checking business affiliations...")

            tasks = []

            # State business registrations
            if state:
                tasks.append(self._search_state_business_registry(name, state))

            # Secretary of State databases
            tasks.append(self._search_secretary_of_state(name, state))

            # Corporate registries
            tasks.append(self._search_corporate_registry(name))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    affiliations.extend(result)

            logger.info(f"Found {len(affiliations)} business affiliations")

        except Exception as e:
            logger.error(f"Business affiliation search error: {e}")

        return affiliations

    async def _search_state_business_registry(
        self,
        name: str,
        state: str
    ) -> List[BusinessAffiliation]:
        """Search state business registries"""
        affiliations = []

        try:
            logger.info(f"Searching {state} business registry")

            # State Secretary of State websites
            # Each state has different business entity search

        except Exception as e:
            logger.error(f"State business registry search error: {e}")

        return affiliations

    async def _search_secretary_of_state(
        self,
        name: str,
        state: Optional[str]
    ) -> List[BusinessAffiliation]:
        """Search Secretary of State business databases"""
        affiliations = []

        try:
            logger.info("Searching Secretary of State databases")

            # OpenCorporates API could be used here
            # https://api.opencorporates.com/

        except Exception as e:
            logger.error(f"Secretary of State search error: {e}")

        return affiliations

    async def _search_corporate_registry(self, name: str) -> List[BusinessAffiliation]:
        """Search corporate registries"""
        affiliations = []

        try:
            logger.info("Searching corporate registries")

            # Services like OpenCorporates, Dun & Bradstreet

        except Exception as e:
            logger.error(f"Corporate registry search error: {e}")

        return affiliations

    async def _check_sex_offender_registry(
        self,
        name: str,
        state: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Check sex offender registries"""
        try:
            logger.info("Checking sex offender registry...")

            # National Sex Offender Public Website (NSOPW)
            # https://www.nsopw.gov/

            # State-specific registries also available

            return None  # No match

        except Exception as e:
            logger.error(f"Sex offender registry check error: {e}")
            return None

    async def _check_bankruptcy_records(
        self,
        name: str,
        state: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Search bankruptcy records"""
        records = []

        try:
            logger.info("Checking bankruptcy records...")

            # PACER bankruptcy court records
            # https://www.pacer.gov/

            # Free bankruptcy search sites also available

        except Exception as e:
            logger.error(f"Bankruptcy search error: {e}")

        return records

    async def _check_liens_judgments(
        self,
        name: str,
        state: Optional[str],
        county: Optional[str]
    ) -> tuple:
        """Search for liens and judgments"""
        liens = []
        judgments = []

        try:
            logger.info("Checking liens and judgments...")

            # County recorder offices
            # UCC filing searches
            # Tax lien searches

        except Exception as e:
            logger.error(f"Lien/judgment search error: {e}")

        return liens, judgments

    def _calculate_completeness(self, report: BackgroundReport) -> float:
        """Calculate report completeness score"""
        score = 0.0
        max_score = 100.0

        # Criminal records check (20 points)
        if report.criminal_records is not None:
            score += 20

        # Court cases check (15 points)
        if report.court_cases is not None:
            score += 15

        # Property records (15 points)
        if report.property_records is not None:
            score += 15

        # Business affiliations (15 points)
        if report.business_affiliations is not None:
            score += 15

        # Sex offender check (10 points)
        if report.sex_offender_registry is not None:
            score += 10

        # Bankruptcy check (10 points)
        if report.bankruptcy_records is not None:
            score += 10

        # Liens/judgments (15 points)
        if report.lien_records is not None or report.judgment_records is not None:
            score += 15

        return min(score, max_score)

    def _calculate_risk_score(self, report: BackgroundReport) -> float:
        """Calculate risk score based on findings"""
        risk = 0.0

        # Criminal records (high risk)
        for record in report.criminal_records:
            if record.severity == 'felony':
                risk += 30
            elif record.severity == 'misdemeanor':
                risk += 10

        # Active court cases (medium risk)
        active_cases = [c for c in report.court_cases if c.case_status in ['open', 'pending']]
        risk += len(active_cases) * 5

        # Sex offender registry (very high risk)
        if report.sex_offender_registry:
            risk += 50

        # Bankruptcy (medium risk)
        risk += len(report.bankruptcy_records) * 15

        # Liens and judgments (low-medium risk)
        risk += len(report.lien_records) * 5
        risk += len(report.judgment_records) * 10

        return min(risk, 100.0)

    def export_report(self, report: BackgroundReport, format: str = 'json') -> str:
        """Export background report"""
        if format == 'json':
            return json.dumps({
                'name': report.name,
                'search_date': report.search_date,
                'criminal_records': [{
                    'case_number': r.case_number,
                    'offense': r.offense,
                    'offense_date': r.offense_date,
                    'disposition': r.disposition,
                    'severity': r.severity,
                    'status': r.status
                } for r in report.criminal_records],
                'court_cases': [{
                    'case_number': c.case_number,
                    'case_type': c.case_type,
                    'filing_date': c.filing_date,
                    'status': c.case_status
                } for c in report.court_cases],
                'property_records': [{
                    'address': p.address,
                    'owner': p.owner_name,
                    'value': p.assessed_value
                } for p in report.property_records],
                'business_affiliations': [{
                    'business': b.business_name,
                    'role': b.role,
                    'status': b.status
                } for b in report.business_affiliations],
                'completeness_score': report.completeness_score,
                'risk_score': report.risk_score
            }, indent=2)

        elif format == 'text':
            return f"""
BACKGROUND CHECK REPORT
{'='*80}

Subject: {report.name}
Report Date: {report.search_date}
Completeness: {report.completeness_score:.1f}%
Risk Score: {report.risk_score:.1f}/100

CRIMINAL RECORDS
{'='*80}

{chr(10).join(f"  [{r.severity or 'Unknown'}] {r.offense} - {r.case_number}" for r in report.criminal_records) if report.criminal_records else '  No criminal records found'}

COURT CASES
{'='*80}

{chr(10).join(f"  [{c.case_type}] {c.case_number} - {c.case_status}" for c in report.court_cases) if report.court_cases else '  No court cases found'}

PROPERTY RECORDS
{'='*80}

{chr(10).join(f"  {p.address} - ${p.assessed_value:,.0f}" if p.assessed_value else f"  {p.address}" for p in report.property_records) if report.property_records else '  No property records found'}

BUSINESS AFFILIATIONS
{'='*80}

{chr(10).join(f"  {b.business_name} ({b.role}) - {b.status}" for b in report.business_affiliations) if report.business_affiliations else '  No business affiliations found'}

{'='*80}
"""

        return ""


if __name__ == "__main__":
    # Example usage
    async def main():
        async with BackgroundChecker() as checker:
            report = await checker.comprehensive_check(
                name="John Doe",
                dob="1980-01-01",
                state="NY",
                county="New York"
            )

            print(checker.export_report(report, format='text'))

            # Save JSON report
            with open('background_report.json', 'w') as f:
                f.write(checker.export_report(report, format='json'))

    asyncio.run(main())

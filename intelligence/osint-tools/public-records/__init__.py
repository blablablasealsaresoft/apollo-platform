"""
Public Records Intelligence System
===================================

Comprehensive public records search system for OSINT investigations.

Components:
-----------
- public_records: Main orchestration engine
- court_records: Court case search (740M+ cases)
- criminal_records: Criminal background checks
- property_records: Property ownership and history
- business_records: Corporate registrations (200M+ companies)
- government_records: Government contracts and campaign finance
- offshore_leaks: ICIJ offshore databases (810K+ entities)

Quick Start:
-----------
>>> from public_records import PublicRecords
>>> records = PublicRecords(config)
>>> results = records.search(name="John Doe", state="NY")
>>> print(f"Found {results['summary']['total_records']} records")

Data Sources:
------------
Court: JudyRecords, CourtListener, PACER, State Courts
Criminal: NSOPW, FBI, USMS, BOP, State DOC
Property: ATTOM, Zillow, County Assessors
Business: OpenCorporates, Secretary of State, SEC EDGAR
Government: USASpending, FEC, Senate LDA
Offshore: Panama Papers, Paradise Papers, Pandora Papers

Author: Agent 16 - Public Records Intelligence
Version: 1.0.0
"""

from .public_records import PublicRecords, SearchQuery, RecordResult
from .court_records import CourtRecordsSearch
from .criminal_records import CriminalRecordsSearch
from .property_records import PropertyRecordsSearch
from .business_records import BusinessRecordsSearch
from .government_records import GovernmentRecordsSearch
from .offshore_leaks import OffshoreLeaksSearch

__version__ = '1.0.0'
__author__ = 'Agent 16 - Public Records Intelligence'

__all__ = [
    'PublicRecords',
    'SearchQuery',
    'RecordResult',
    'CourtRecordsSearch',
    'CriminalRecordsSearch',
    'PropertyRecordsSearch',
    'BusinessRecordsSearch',
    'GovernmentRecordsSearch',
    'OffshoreLeaksSearch',
]

# Data source statistics
DATA_SOURCES = {
    'court_records': {
        'judy_records': '740M+ cases',
        'court_listener': 'Federal and state opinions',
        'pacer': 'Federal court system',
        'state_courts': '50 state systems'
    },
    'criminal_records': {
        'nsopw': '900K+ sex offenders',
        'fbi_most_wanted': 'Ten Most Wanted',
        'usms_most_wanted': 'Fugitives',
        'bop': 'Federal inmates',
        'state_doc': '50 state corrections'
    },
    'property_records': {
        'attom': '150M+ properties',
        'zillow': 'Property valuations',
        'county_assessors': 'Tax assessments',
        'county_recorders': 'Deeds and mortgages'
    },
    'business_records': {
        'opencorporates': '200M+ companies',
        'secretary_of_state': '50 states',
        'sec_edgar': 'Public companies',
        'ucc_filings': 'Secured transactions'
    },
    'government_records': {
        'usaspending': 'Federal contracts',
        'fec': 'Campaign finance',
        'senate_lda': 'Lobbying disclosures',
        'muckrock': 'FOIA requests'
    },
    'offshore_leaks': {
        'panama_papers': '214,488 entities',
        'paradise_papers': '120,000+ entities',
        'pandora_papers': '29,000+ entities',
        'offshore_leaks': '130,000+ entities',
        'bahamas_leaks': '175,000+ entities',
        'total': '810,000+ entities'
    }
}

def get_data_source_info():
    """Get information about available data sources"""
    return DATA_SOURCES

def get_supported_states():
    """Get list of supported US states"""
    return [
        'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
        'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
        'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
        'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
        'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY'
    ]

def get_version():
    """Get package version"""
    return __version__

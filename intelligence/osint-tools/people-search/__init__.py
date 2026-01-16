"""
People Search & Background Intelligence System
Comprehensive OSINT toolkit for people investigation
"""

from .people_search import PeopleSearch, PeopleSearchSync, PersonProfile
from .spokeo_integration import SpokeoIntegration, SpokeoProfile
from .pipl_integration import PiplIntegration, PiplPerson
from .truepeoplesearch import TruePeopleSearch, TruePeopleProfile
from .background_checker import BackgroundChecker, BackgroundReport, CriminalRecord, CourtCase
from .voter_records import VoterRecordsSearch, VoterRecord
from .social_profile_aggregator import SocialProfileAggregator, SocialNetwork, SocialProfile

__version__ = "1.0.0"
__author__ = "OSINT Research Team"

__all__ = [
    # Main search
    'PeopleSearch',
    'PeopleSearchSync',
    'PersonProfile',

    # Spokeo
    'SpokeoIntegration',
    'SpokeoProfile',

    # Pipl
    'PiplIntegration',
    'PiplPerson',

    # TruePeopleSearch
    'TruePeopleSearch',
    'TruePeopleProfile',

    # Background
    'BackgroundChecker',
    'BackgroundReport',
    'CriminalRecord',
    'CourtCase',

    # Voter
    'VoterRecordsSearch',
    'VoterRecord',

    # Social
    'SocialProfileAggregator',
    'SocialNetwork',
    'SocialProfile',
]

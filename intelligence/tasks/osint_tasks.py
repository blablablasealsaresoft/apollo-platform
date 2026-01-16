"""
OSINT Celery Tasks
Username search, domain scanning, email/phone intelligence
"""

from celery import Task
from celery.utils.log import get_task_logger
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celery_tasks import app
from config import settings

logger = get_task_logger(__name__)


def run_async(coro):
    """Run async coroutine in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(
    bind=True,
    name='intelligence.osint.username_search',
    max_retries=3,
    default_retry_delay=60
)
def search_username_task(
    self: Task,
    username: str,
    platforms: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Search for username across social media platforms using Sherlock

    Args:
        username: Username to search
        platforms: List of platform names (None = all platforms)

    Returns:
        Dictionary with search results
    """
    logger.info(f"[{self.request.id}] Starting username search for: {username}")

    try:
        from osint_tools.sherlock import SherlockEngine

        engine = SherlockEngine()
        results = run_async(engine.search_username(username, platforms))

        found_platforms = [r for r in results if r.status == 'found']

        logger.info(
            f"[{self.request.id}] Username search completed: "
            f"{len(found_platforms)} profiles found"
        )

        return {
            'task_id': self.request.id,
            'username': username,
            'total_platforms_checked': len(results),
            'profiles_found': len(found_platforms),
            'results': [
                {
                    'platform': r.platform,
                    'url': r.url,
                    'status': r.status,
                    'confidence_score': r.confidence_score,
                    'response_time_ms': r.response_time_ms,
                }
                for r in found_platforms
            ],
            'summary': {
                'found': len([r for r in results if r.status == 'found']),
                'not_found': len([r for r in results if r.status == 'not_found']),
                'errors': len([r for r in results if r.status == 'error']),
                'rate_limited': len([r for r in results if r.status == 'rate_limited']),
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Username search failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.osint.batch_search',
    max_retries=3,
    default_retry_delay=120
)
def batch_search_usernames_task(
    self: Task,
    usernames: List[str],
    platforms: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Batch search for multiple usernames

    Args:
        usernames: List of usernames to search
        platforms: List of platform names

    Returns:
        Dictionary with batch results
    """
    logger.info(
        f"[{self.request.id}] Starting batch search for "
        f"{len(usernames)} usernames"
    )

    try:
        from osint_tools.sherlock import SherlockEngine, BatchUsernameProcessor

        engine = SherlockEngine()
        processor = BatchUsernameProcessor(engine)
        batch_result = run_async(processor.search_batch(usernames, platforms))

        logger.info(
            f"[{self.request.id}] Batch search completed: "
            f"{batch_result.found_results} results found"
        )

        return {
            'task_id': self.request.id,
            'total_usernames': batch_result.total_usernames,
            'total_platforms': batch_result.total_platforms,
            'found_results': batch_result.found_results,
            'duration_seconds': batch_result.duration_seconds,
            'results_per_username': {
                username: len([
                    r for r in batch_result.all_results
                    if r.username == username and r.status == 'found'
                ])
                for username in usernames
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Batch search failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.osint.domain_scan',
    max_retries=2,
    default_retry_delay=300
)
def domain_scan_task(
    self: Task,
    domain: str,
    scan_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Comprehensive domain scan using BBOT

    Args:
        domain: Target domain
        scan_types: Types of scans to perform

    Returns:
        Dictionary with scan results
    """
    logger.info(f"[{self.request.id}] Starting domain scan for: {domain}")

    try:
        from osint_tools.bbot import BBOTEngine

        engine = BBOTEngine()
        result = run_async(engine.full_scan(domain, scan_types))

        logger.info(
            f"[{self.request.id}] Domain scan completed: "
            f"{result.subdomains_found} subdomains found"
        )

        return {
            'task_id': self.request.id,
            'target': result.target,
            'scan_types': scan_types or ['default'],
            'subdomains_found': result.subdomains_found,
            'ips_found': result.ips_found,
            'ports_found': result.ports_found,
            'technologies_found': result.technologies_found,
            'vulnerabilities_found': result.vulnerabilities_found,
            'dns_records': result.dns_records,
            'email_addresses': result.email_addresses,
            'duration_seconds': result.duration_seconds,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Domain scan failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.osint.email_intelligence',
    max_retries=3,
    default_retry_delay=60
)
def email_intelligence_task(
    self: Task,
    email: str
) -> Dict[str, Any]:
    """
    Gather intelligence about an email address

    Args:
        email: Email address to investigate

    Returns:
        Dictionary with email intelligence
    """
    logger.info(f"[{self.request.id}] Starting email intelligence for: {email}")

    try:
        from breach_databases import BreachDatabaseEngine

        engine = BreachDatabaseEngine()
        breaches = run_async(engine.search_email(email))

        logger.info(
            f"[{self.request.id}] Email intelligence completed: "
            f"{len(breaches)} breaches found"
        )

        return {
            'task_id': self.request.id,
            'email': email,
            'total_breaches': len(breaches),
            'breaches': [
                {
                    'breach_name': b.breach_name,
                    'breach_date': b.breach_date.isoformat() if b.breach_date else None,
                    'data_types': b.data_types,
                    'source': b.source,
                    'password_exposed': b.password_exposed,
                }
                for b in breaches[:50]  # Limit to 50 most recent
            ],
            'data_types_exposed': list(set(
                dt for b in breaches for dt in b.data_types
            )),
            'risk_assessment': {
                'risk_level': 'HIGH' if len(breaches) > 5 else 'MEDIUM' if len(breaches) > 0 else 'LOW',
                'password_breaches': len([b for b in breaches if b.password_exposed]),
                'recent_breaches': len([
                    b for b in breaches
                    if b.breach_date and (datetime.now() - b.breach_date).days < 365
                ]),
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Email intelligence failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.osint.phone_intelligence',
    max_retries=3,
    default_retry_delay=60
)
def phone_intelligence_task(
    self: Task,
    phone: str
) -> Dict[str, Any]:
    """
    Gather intelligence about a phone number

    Args:
        phone: Phone number to investigate

    Returns:
        Dictionary with phone intelligence
    """
    logger.info(f"[{self.request.id}] Starting phone intelligence for: {phone}")

    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone

        # Parse phone number
        try:
            parsed = phonenumbers.parse(phone, None)
        except phonenumbers.NumberParseException:
            # Try with US as default
            parsed = phonenumbers.parse(phone, "US")

        # Extract intelligence
        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        country = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        timezones = timezone.time_zones_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)

        # Map number type
        type_map = {
            0: 'FIXED_LINE',
            1: 'MOBILE',
            2: 'FIXED_LINE_OR_MOBILE',
            3: 'TOLL_FREE',
            4: 'PREMIUM_RATE',
            5: 'SHARED_COST',
            6: 'VOIP',
            7: 'PERSONAL_NUMBER',
            8: 'PAGER',
            9: 'UAN',
            10: 'VOICEMAIL',
            99: 'UNKNOWN',
        }

        logger.info(f"[{self.request.id}] Phone intelligence completed")

        return {
            'task_id': self.request.id,
            'phone': phone,
            'parsed': {
                'international': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                'national': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                ),
                'e164': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                ),
            },
            'validity': {
                'is_valid': is_valid,
                'is_possible': is_possible,
            },
            'location': {
                'country': country,
                'country_code': parsed.country_code,
                'timezones': list(timezones),
            },
            'carrier': carrier_name,
            'number_type': type_map.get(number_type, 'UNKNOWN'),
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Phone intelligence failed: {exc}")
        return {
            'task_id': self.request.id,
            'phone': phone,
            'error': str(exc),
            'completed_at': datetime.now().isoformat()
        }


@app.task(
    bind=True,
    name='intelligence.osint.ip_intelligence',
    max_retries=3,
    default_retry_delay=60
)
def ip_intelligence_task(
    self: Task,
    ip_address: str
) -> Dict[str, Any]:
    """
    Gather intelligence about an IP address

    Args:
        ip_address: IP address to investigate

    Returns:
        Dictionary with IP intelligence
    """
    logger.info(f"[{self.request.id}] Starting IP intelligence for: {ip_address}")

    try:
        import requests

        intelligence = {
            'task_id': self.request.id,
            'ip': ip_address,
            'geolocation': {},
            'asn': {},
            'threat_intelligence': {},
        }

        # Use ipinfo.io (free tier)
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                intelligence['geolocation'] = {
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'location': data.get('loc'),
                    'postal': data.get('postal'),
                    'timezone': data.get('timezone'),
                }
                intelligence['asn'] = {
                    'org': data.get('org'),
                    'hostname': data.get('hostname'),
                }
        except Exception as e:
            logger.warning(f"IPInfo lookup failed: {e}")

        logger.info(f"[{self.request.id}] IP intelligence completed")

        intelligence['completed_at'] = datetime.now().isoformat()
        return intelligence

    except Exception as exc:
        logger.error(f"[{self.request.id}] IP intelligence failed: {exc}")
        raise self.retry(exc=exc)

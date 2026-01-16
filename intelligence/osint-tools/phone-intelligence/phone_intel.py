"""
Phone Intelligence - Main Module
Comprehensive phone number investigation and intelligence gathering
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from phone_validator import PhoneValidator
from phoneinfoga_integration import PhoneInfogaClient
from truecaller_integration import TrueCallerClient
from hlr_lookup import HLRLookup
from sms_intelligence import SMSIntelligence
from voip_intelligence import VoIPIntelligence
from phone_correlator import PhoneCorrelator


class PhoneIntelligence:
    """
    Main phone intelligence gathering system
    Aggregates data from multiple sources for comprehensive phone analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize phone intelligence system

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # Initialize sub-modules
        self.validator = PhoneValidator()
        self.phoneinfoga = PhoneInfogaClient(self.config.get('phoneinfoga', {}))
        self.truecaller = TrueCallerClient(self.config.get('truecaller', {}))
        self.hlr = HLRLookup(self.config.get('hlr', {}))
        self.sms_intel = SMSIntelligence(self.config.get('sms', {}))
        self.voip = VoIPIntelligence(self.config.get('voip', {}))
        self.correlator = PhoneCorrelator(self.config.get('correlator', {}))

        self.logger.info("Phone Intelligence system initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('PhoneIntelligence')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def normalize_phone(self, phone: str, default_region: str = "US") -> Optional[str]:
        """
        Normalize phone number to E.164 format

        Args:
            phone: Phone number in any format
            default_region: Default country code if not specified

        Returns:
            Normalized phone number or None if invalid
        """
        try:
            # Parse phone number
            parsed = phonenumbers.parse(phone, default_region)

            # Validate
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.E164
                )
            return None
        except Exception as e:
            self.logger.error(f"Error normalizing phone {phone}: {e}")
            return None

    def investigate(self, phone: str, deep: bool = True) -> Dict[str, Any]:
        """
        Comprehensive phone number investigation

        Args:
            phone: Phone number to investigate
            deep: Whether to perform deep investigation (slower)

        Returns:
            Dictionary with all gathered intelligence
        """
        self.logger.info(f"Starting investigation for: {phone}")

        # Normalize phone number
        normalized = self.normalize_phone(phone)
        if not normalized:
            return {
                'error': 'Invalid phone number',
                'raw_input': phone,
                'timestamp': datetime.utcnow().isoformat()
            }

        results = {
            'phone_number': normalized,
            'raw_input': phone,
            'timestamp': datetime.utcnow().isoformat(),
            'basic_info': {},
            'validation': {},
            'carrier_info': {},
            'caller_id': {},
            'location': {},
            'network': {},
            'voip_analysis': {},
            'sms_analysis': {},
            'social_media': {},
            'breaches': {},
            'correlations': {},
            'risk_score': 0
        }

        # Run basic validation first
        results['validation'] = self.validator.validate(normalized)

        if not results['validation'].get('is_valid'):
            results['error'] = 'Phone number validation failed'
            return results

        # Gather basic information
        results['basic_info'] = self._get_basic_info(normalized)

        # Parallel data gathering for speed
        tasks = {
            'phoneinfoga': lambda: self.phoneinfoga.lookup(normalized),
            'caller_id': lambda: self.truecaller.lookup(normalized),
            'voip': lambda: self.voip.analyze(normalized),
            'sms': lambda: self.sms_intel.analyze(normalized)
        }

        if deep:
            tasks.update({
                'hlr': lambda: self.hlr.lookup(normalized),
                'correlations': lambda: self.correlator.correlate(normalized)
            })

        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_task = {
                executor.submit(task): name
                for name, task in tasks.items()
            }

            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    result = future.result(timeout=30)

                    if task_name == 'phoneinfoga':
                        results['carrier_info'] = result.get('carrier', {})
                        results['location'] = result.get('location', {})
                    elif task_name == 'caller_id':
                        results['caller_id'] = result
                    elif task_name == 'hlr':
                        results['network'] = result
                    elif task_name == 'voip':
                        results['voip_analysis'] = result
                    elif task_name == 'sms':
                        results['sms_analysis'] = result
                    elif task_name == 'correlations':
                        results['social_media'] = result.get('social_media', {})
                        results['breaches'] = result.get('breaches', {})
                        results['correlations'] = result.get('correlations', {})

                except Exception as e:
                    self.logger.error(f"Error in {task_name}: {e}")
                    results[task_name + '_error'] = str(e)

        # Calculate risk score
        results['risk_score'] = self._calculate_risk_score(results)

        # Generate summary
        results['summary'] = self._generate_summary(results)

        self.logger.info(f"Investigation completed for: {normalized}")
        return results

    def _get_basic_info(self, phone: str) -> Dict[str, Any]:
        """Get basic phone number information using phonenumbers library"""
        try:
            parsed = phonenumbers.parse(phone)

            info = {
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'country': geocoder.description_for_number(parsed, 'en'),
                'region': phonenumbers.region_code_for_number(parsed),
                'carrier': carrier.name_for_number(parsed, 'en'),
                'timezones': timezone.time_zones_for_number(parsed),
                'number_type': self._get_number_type(parsed),
                'formatted': {
                    'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                    'rfc3966': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)
                }
            }

            return info
        except Exception as e:
            self.logger.error(f"Error getting basic info: {e}")
            return {}

    def _get_number_type(self, parsed_number) -> str:
        """Get human-readable number type"""
        number_type = phonenumbers.number_type(parsed_number)

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
            -1: 'UNKNOWN'
        }

        return type_map.get(number_type, 'UNKNOWN')

    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """
        Calculate risk score based on gathered intelligence

        Returns:
            Risk score from 0-100 (0 = low risk, 100 = high risk)
        """
        score = 0

        # VoIP numbers are higher risk
        if results.get('voip_analysis', {}).get('is_voip'):
            score += 20

        # Numbers in breach databases
        breach_count = len(results.get('breaches', {}).get('found_in', []))
        score += min(breach_count * 10, 30)

        # Spam reports
        if results.get('caller_id', {}).get('spam_score', 0) > 50:
            score += 15

        # Disposable/temporary numbers
        if results.get('sms_analysis', {}).get('is_disposable'):
            score += 25

        # No carrier information (suspicious)
        if not results.get('carrier_info', {}).get('name'):
            score += 10

        # Invalid HLR lookup (number may not exist)
        if results.get('network', {}).get('status') == 'INACTIVE':
            score += 15

        return min(score, 100)

    def _generate_summary(self, results: Dict[str, Any]) -> str:
        """Generate human-readable summary of findings"""
        summary_parts = []

        # Basic info
        basic = results.get('basic_info', {})
        if basic.get('carrier'):
            summary_parts.append(f"Carrier: {basic['carrier']}")
        if basic.get('country'):
            summary_parts.append(f"Location: {basic['country']}")
        if basic.get('number_type'):
            summary_parts.append(f"Type: {basic['number_type']}")

        # VoIP
        if results.get('voip_analysis', {}).get('is_voip'):
            provider = results['voip_analysis'].get('provider', 'Unknown')
            summary_parts.append(f"VoIP number ({provider})")

        # Caller ID
        caller_id = results.get('caller_id', {})
        if caller_id.get('name'):
            summary_parts.append(f"Registered to: {caller_id['name']}")

        # Spam
        if caller_id.get('spam_score', 0) > 50:
            summary_parts.append("WARNING: Reported as spam")

        # Breaches
        breach_count = len(results.get('breaches', {}).get('found_in', []))
        if breach_count > 0:
            summary_parts.append(f"Found in {breach_count} data breach(es)")

        # Risk
        risk = results.get('risk_score', 0)
        if risk > 70:
            summary_parts.append("HIGH RISK")
        elif risk > 40:
            summary_parts.append("MODERATE RISK")
        else:
            summary_parts.append("LOW RISK")

        return " | ".join(summary_parts) if summary_parts else "No significant findings"

    def batch_investigate(self, phones: List[str], deep: bool = False) -> Dict[str, Any]:
        """
        Investigate multiple phone numbers

        Args:
            phones: List of phone numbers
            deep: Whether to perform deep investigation

        Returns:
            Dictionary mapping phone numbers to results
        """
        self.logger.info(f"Starting batch investigation for {len(phones)} numbers")

        results = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_phone = {
                executor.submit(self.investigate, phone, deep): phone
                for phone in phones
            }

            for future in as_completed(future_to_phone):
                phone = future_to_phone[future]
                try:
                    results[phone] = future.result()
                except Exception as e:
                    self.logger.error(f"Error investigating {phone}: {e}")
                    results[phone] = {'error': str(e)}

        return results

    def export_report(self, results: Dict[str, Any], format: str = 'json') -> str:
        """
        Export investigation results

        Args:
            results: Investigation results
            format: Export format (json, html, txt)

        Returns:
            Formatted report as string
        """
        if format == 'json':
            return json.dumps(results, indent=2, default=str)

        elif format == 'txt':
            lines = [
                "=" * 60,
                "PHONE INTELLIGENCE REPORT",
                "=" * 60,
                f"Phone Number: {results.get('phone_number')}",
                f"Investigation Time: {results.get('timestamp')}",
                f"Risk Score: {results.get('risk_score')}/100",
                "",
                "SUMMARY:",
                results.get('summary', 'No summary available'),
                "",
                "=" * 60
            ]

            # Add sections
            sections = [
                ('BASIC INFORMATION', 'basic_info'),
                ('CARRIER INFORMATION', 'carrier_info'),
                ('CALLER ID', 'caller_id'),
                ('LOCATION', 'location'),
                ('NETWORK STATUS', 'network'),
                ('VOIP ANALYSIS', 'voip_analysis'),
                ('SMS ANALYSIS', 'sms_analysis'),
                ('SOCIAL MEDIA', 'social_media'),
                ('DATA BREACHES', 'breaches')
            ]

            for title, key in sections:
                data = results.get(key, {})
                if data:
                    lines.append(f"\n{title}:")
                    lines.append("-" * 60)
                    for k, v in data.items():
                        lines.append(f"  {k}: {v}")

            return "\n".join(lines)

        elif format == 'html':
            # Basic HTML report
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Phone Intelligence Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .section {{ margin: 20px 0; padding: 10px; background: #f5f5f5; }}
                    .risk-high {{ color: red; font-weight: bold; }}
                    .risk-medium {{ color: orange; font-weight: bold; }}
                    .risk-low {{ color: green; font-weight: bold; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #4CAF50; color: white; }}
                </style>
            </head>
            <body>
                <h1>Phone Intelligence Report</h1>
                <div class="section">
                    <h2>Overview</h2>
                    <p><strong>Phone Number:</strong> {results.get('phone_number')}</p>
                    <p><strong>Investigation Time:</strong> {results.get('timestamp')}</p>
                    <p><strong>Risk Score:</strong> <span class="risk-{self._get_risk_class(results.get('risk_score', 0))}">{results.get('risk_score')}/100</span></p>
                    <p><strong>Summary:</strong> {results.get('summary')}</p>
                </div>
                <div class="section">
                    <h2>Detailed Findings</h2>
                    <pre>{json.dumps(results, indent=2, default=str)}</pre>
                </div>
            </body>
            </html>
            """
            return html

        else:
            raise ValueError(f"Unsupported format: {format}")

    def _get_risk_class(self, score: int) -> str:
        """Get CSS class for risk score"""
        if score > 70:
            return 'high'
        elif score > 40:
            return 'medium'
        else:
            return 'low'


def main():
    """Example usage"""
    # Configuration with API keys
    config = {
        'truecaller': {
            'api_key': 'YOUR_TRUECALLER_API_KEY'
        },
        'hlr': {
            'api_key': 'YOUR_HLR_API_KEY'
        }
    }

    # Initialize system
    phone_intel = PhoneIntelligence(config)

    # Investigate a phone number
    result = phone_intel.investigate("+1-555-0123", deep=True)

    # Print summary
    print(result['summary'])

    # Export full report
    report = phone_intel.export_report(result, format='txt')
    print(report)

    # Batch investigation
    numbers = ["+1-555-0123", "+44-20-7123-4567", "+91-98765-43210"]
    batch_results = phone_intel.batch_investigate(numbers)

    for number, data in batch_results.items():
        print(f"\n{number}: {data.get('summary')}")


if __name__ == "__main__":
    main()

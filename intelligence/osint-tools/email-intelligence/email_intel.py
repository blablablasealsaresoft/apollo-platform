"""
Email Intelligence System - Main Module
Comprehensive email OSINT and intelligence gathering
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from email_validator import EmailValidator
from email_reputation import EmailReputation
from holehe_integration import HoleheIntegration
from email_hunter import EmailHunter
from email_format import EmailFormatFinder
from email_header_analyzer import EmailHeaderAnalyzer
from email_correlator import EmailCorrelator


@dataclass
class EmailProfile:
    """Complete email intelligence profile"""
    email: str
    timestamp: str
    validation: Dict[str, Any]
    reputation: Dict[str, Any]
    accounts: List[Dict[str, Any]]
    breaches: List[Dict[str, Any]]
    social_media: List[Dict[str, Any]]
    related_emails: List[str]
    related_usernames: List[str]
    domain_info: Dict[str, Any]
    risk_score: float
    summary: Dict[str, Any]


class EmailIntelligence:
    """
    Main Email Intelligence System
    Orchestrates all email OSINT modules
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Email Intelligence System

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # Initialize modules
        self.validator = EmailValidator()
        self.reputation = EmailReputation(
            api_key=self.config.get('emailrep_api_key')
        )
        self.holehe = HoleheIntegration()
        self.hunter = EmailHunter(
            api_key=self.config.get('hunter_api_key')
        )
        self.format_finder = EmailFormatFinder()
        self.header_analyzer = EmailHeaderAnalyzer()
        self.correlator = EmailCorrelator()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailIntelligence')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def investigate(self, email: str, deep: bool = True) -> EmailProfile:
        """
        Comprehensive email investigation

        Args:
            email: Email address to investigate
            deep: Perform deep investigation (slower but more thorough)

        Returns:
            EmailProfile with all gathered intelligence
        """
        self.logger.info(f"Starting investigation for: {email}")

        # Basic validation
        validation = self.validator.validate(email)
        if not validation['valid']:
            self.logger.warning(f"Invalid email: {email}")
            return self._create_invalid_profile(email, validation)

        # Gather intelligence in parallel
        results = {}

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(self._get_reputation, email): 'reputation',
                executor.submit(self._find_accounts, email): 'accounts',
                executor.submit(self._check_breaches, email): 'breaches',
                executor.submit(self._extract_domain_info, email): 'domain_info',
            }

            if deep:
                futures[executor.submit(self._find_related_emails, email)] = 'related_emails'
                futures[executor.submit(self._find_social_media, email)] = 'social_media'

            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    self.logger.error(f"Error in {key}: {str(e)}")
                    results[key] = self._get_default_result(key)

        # Correlation analysis
        correlation = self.correlator.correlate(email, results)

        # Calculate risk score
        risk_score = self._calculate_risk_score(validation, results)

        # Create profile
        profile = EmailProfile(
            email=email,
            timestamp=datetime.now().isoformat(),
            validation=validation,
            reputation=results.get('reputation', {}),
            accounts=results.get('accounts', []),
            breaches=results.get('breaches', []),
            social_media=results.get('social_media', []),
            related_emails=correlation.get('related_emails', []),
            related_usernames=correlation.get('related_usernames', []),
            domain_info=results.get('domain_info', {}),
            risk_score=risk_score,
            summary=self._generate_summary(email, results, risk_score)
        )

        self.logger.info(f"Investigation completed for: {email}")
        return profile

    def _get_reputation(self, email: str) -> Dict[str, Any]:
        """Get email reputation"""
        try:
            return self.reputation.check(email)
        except Exception as e:
            self.logger.error(f"Reputation check failed: {str(e)}")
            return {}

    def _find_accounts(self, email: str) -> List[Dict[str, Any]]:
        """Find accounts associated with email"""
        try:
            accounts = self.holehe.check(email)
            return accounts
        except Exception as e:
            self.logger.error(f"Account enumeration failed: {str(e)}")
            return []

    def _check_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check for data breaches"""
        try:
            # This would integrate with HIBP or similar
            return self.correlator.check_breaches(email)
        except Exception as e:
            self.logger.error(f"Breach check failed: {str(e)}")
            return []

    def _find_related_emails(self, email: str) -> List[str]:
        """Find related email addresses"""
        try:
            domain = email.split('@')[1]
            username = email.split('@')[0]

            # Search for variations
            related = self.correlator.find_email_variations(username, domain)
            return related
        except Exception as e:
            self.logger.error(f"Related email search failed: {str(e)}")
            return []

    def _find_social_media(self, email: str) -> List[Dict[str, Any]]:
        """Find social media accounts"""
        try:
            return self.correlator.find_social_media(email)
        except Exception as e:
            self.logger.error(f"Social media search failed: {str(e)}")
            return []

    def _extract_domain_info(self, email: str) -> Dict[str, Any]:
        """Extract domain information"""
        try:
            domain = email.split('@')[1]
            return {
                'domain': domain,
                'mx_records': self.validator.get_mx_records(domain),
                'spf_record': self.validator.get_spf_record(domain),
                'dmarc_record': self.validator.get_dmarc_record(domain),
                'company_info': self.hunter.get_domain_info(domain)
            }
        except Exception as e:
            self.logger.error(f"Domain info extraction failed: {str(e)}")
            return {'domain': email.split('@')[1] if '@' in email else ''}

    def _calculate_risk_score(self, validation: Dict, results: Dict) -> float:
        """
        Calculate risk score (0-100)
        Higher score = higher risk
        """
        score = 0.0

        # Validation issues
        if validation.get('disposable'):
            score += 30
        if validation.get('role_based'):
            score += 10
        if not validation.get('mx_valid'):
            score += 20

        # Reputation
        reputation = results.get('reputation', {})
        if reputation.get('suspicious', False):
            score += 25
        if reputation.get('malicious', False):
            score += 40

        spam_score = reputation.get('spam_score', 0)
        score += min(spam_score * 0.2, 20)  # Up to 20 points from spam score

        # Breaches
        breach_count = len(results.get('breaches', []))
        score += min(breach_count * 5, 25)  # Up to 25 points from breaches

        return min(score, 100.0)

    def _generate_summary(self, email: str, results: Dict, risk_score: float) -> Dict[str, Any]:
        """Generate investigation summary"""
        return {
            'email': email,
            'risk_level': self._get_risk_level(risk_score),
            'risk_score': risk_score,
            'total_accounts': len(results.get('accounts', [])),
            'total_breaches': len(results.get('breaches', [])),
            'total_social_media': len(results.get('social_media', [])),
            'reputation_status': results.get('reputation', {}).get('reputation', 'unknown'),
            'key_findings': self._extract_key_findings(results)
        }

    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _extract_key_findings(self, results: Dict) -> List[str]:
        """Extract key findings from results"""
        findings = []

        reputation = results.get('reputation', {})
        if reputation.get('malicious'):
            findings.append('Email associated with malicious activity')
        if reputation.get('suspicious'):
            findings.append('Email flagged as suspicious')

        breaches = results.get('breaches', [])
        if breaches:
            findings.append(f'Found in {len(breaches)} data breach(es)')

        accounts = results.get('accounts', [])
        if len(accounts) > 10:
            findings.append(f'Registered on {len(accounts)}+ platforms')

        return findings

    def _create_invalid_profile(self, email: str, validation: Dict) -> EmailProfile:
        """Create profile for invalid email"""
        return EmailProfile(
            email=email,
            timestamp=datetime.now().isoformat(),
            validation=validation,
            reputation={},
            accounts=[],
            breaches=[],
            social_media=[],
            related_emails=[],
            related_usernames=[],
            domain_info={},
            risk_score=0.0,
            summary={
                'email': email,
                'risk_level': 'UNKNOWN',
                'risk_score': 0.0,
                'total_accounts': 0,
                'total_breaches': 0,
                'total_social_media': 0,
                'reputation_status': 'invalid',
                'key_findings': ['Invalid email format']
            }
        )

    def _get_default_result(self, key: str) -> Any:
        """Get default result for failed operations"""
        defaults = {
            'reputation': {},
            'accounts': [],
            'breaches': [],
            'related_emails': [],
            'social_media': [],
            'domain_info': {}
        }
        return defaults.get(key, None)

    def analyze_headers(self, headers: str) -> Dict[str, Any]:
        """
        Analyze email headers

        Args:
            headers: Raw email headers

        Returns:
            Header analysis results
        """
        return self.header_analyzer.analyze(headers)

    def find_company_emails(self, domain: str, pattern: Optional[str] = None) -> List[str]:
        """
        Find emails for a company domain

        Args:
            domain: Company domain
            pattern: Email pattern (e.g., "{first}.{last}")

        Returns:
            List of discovered emails
        """
        try:
            if pattern:
                return self.format_finder.generate_emails(domain, pattern)
            else:
                return self.hunter.find_emails(domain)
        except Exception as e:
            self.logger.error(f"Company email search failed: {str(e)}")
            return []

    def verify_email(self, email: str) -> bool:
        """
        Quick email verification

        Args:
            email: Email to verify

        Returns:
            True if email is valid and deliverable
        """
        validation = self.validator.validate(email)
        return (validation.get('valid', False) and
                validation.get('mx_valid', False) and
                not validation.get('disposable', False))

    def export_profile(self, profile: EmailProfile, format: str = 'json') -> str:
        """
        Export profile to various formats

        Args:
            profile: Email profile to export
            format: Export format (json, csv, html)

        Returns:
            Exported data as string
        """
        if format == 'json':
            return json.dumps(asdict(profile), indent=2)
        elif format == 'csv':
            return self._export_csv(profile)
        elif format == 'html':
            return self._export_html(profile)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_csv(self, profile: EmailProfile) -> str:
        """Export profile as CSV"""
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(['Field', 'Value'])
        writer.writerow(['Email', profile.email])
        writer.writerow(['Risk Score', profile.risk_score])
        writer.writerow(['Risk Level', profile.summary['risk_level']])
        writer.writerow(['Total Accounts', len(profile.accounts)])
        writer.writerow(['Total Breaches', len(profile.breaches)])

        return output.getvalue()

    def _export_html(self, profile: EmailProfile) -> str:
        """Export profile as HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Intelligence Report - {profile.email}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .risk-high {{ color: #e74c3c; font-weight: bold; }}
                .risk-medium {{ color: #f39c12; font-weight: bold; }}
                .risk-low {{ color: #27ae60; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Email Intelligence Report</h1>
                <p>{profile.email}</p>
                <p>Generated: {profile.timestamp}</p>
            </div>

            <div class="section">
                <h2>Risk Assessment</h2>
                <p>Risk Score: <span class="risk-{profile.summary['risk_level'].lower()}">{profile.risk_score}/100</span></p>
                <p>Risk Level: {profile.summary['risk_level']}</p>
            </div>

            <div class="section">
                <h2>Summary</h2>
                <ul>
                    <li>Total Accounts: {len(profile.accounts)}</li>
                    <li>Total Breaches: {len(profile.breaches)}</li>
                    <li>Social Media Profiles: {len(profile.social_media)}</li>
                </ul>
            </div>

            <div class="section">
                <h2>Key Findings</h2>
                <ul>
                    {''.join(f'<li>{finding}</li>' for finding in profile.summary['key_findings'])}
                </ul>
            </div>
        </body>
        </html>
        """
        return html

    def batch_investigate(self, emails: List[str], workers: int = 5) -> List[EmailProfile]:
        """
        Investigate multiple emails in parallel

        Args:
            emails: List of emails to investigate
            workers: Number of parallel workers

        Returns:
            List of EmailProfiles
        """
        profiles = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.investigate, email): email for email in emails}

            for future in as_completed(futures):
                email = futures[future]
                try:
                    profile = future.result()
                    profiles.append(profile)
                except Exception as e:
                    self.logger.error(f"Failed to investigate {email}: {str(e)}")

        return profiles


if __name__ == "__main__":
    # Example usage
    config = {
        'emailrep_api_key': 'YOUR_API_KEY',
        'hunter_api_key': 'YOUR_API_KEY'
    }

    email_intel = EmailIntelligence(config)

    # Single investigation
    profile = email_intel.investigate("target@example.com")
    print(json.dumps(asdict(profile), indent=2))

    # Batch investigation
    emails = ["email1@example.com", "email2@example.com", "email3@example.com"]
    profiles = email_intel.batch_investigate(emails)
    print(f"Investigated {len(profiles)} emails")

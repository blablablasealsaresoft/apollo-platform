"""
Gophish Phishing Infrastructure Integration

CRITICAL: AUTHORIZED OPERATIONS ONLY
"""

from typing import Dict, List, Optional
from datetime import datetime
import uuid


class PhishingCampaign:
    """Represents a phishing campaign"""

    def __init__(
        self,
        campaign_id: str,
        name: str,
        template_id: str,
        landing_page_id: str,
        targets: List[Dict]
    ):
        self.campaign_id = campaign_id
        self.name = name
        self.template_id = template_id
        self.landing_page_id = landing_page_id
        self.targets = targets
        self.status = 'pending'
        self.created_at = datetime.utcnow()
        self.results: Dict[str, Dict] = {}


class GophishManager:
    """
    Gophish Phishing Infrastructure Manager

    CRITICAL: AUTHORIZED USE ONLY
    For security awareness training and authorized red team operations
    """

    def __init__(self, api_url: str = 'http://localhost:3333', api_key: Optional[str] = None):
        self.api_url = api_url
        self.api_key = api_key
        self.campaigns: Dict[str, PhishingCampaign] = {}
        self.templates: Dict[str, Dict] = {}
        self.landing_pages: Dict[str, Dict] = {}

    def create_email_template(
        self,
        name: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> str:
        """
        Create email template

        Args:
            name: Template name
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text body
        """
        template_id = str(uuid.uuid4())

        template = {
            'id': template_id,
            'name': name,
            'subject': subject,
            'html': html_body,
            'text': text_body or '',
            'created_at': datetime.utcnow().isoformat()
        }

        self.templates[template_id] = template
        print(f"[Gophish] Created template: {name}")

        return template_id

    def create_landing_page(
        self,
        name: str,
        html: str,
        capture_credentials: bool = True,
        capture_passwords: bool = False
    ) -> str:
        """
        Create phishing landing page

        Args:
            name: Page name
            html: HTML content
            capture_credentials: Whether to capture submitted credentials
            capture_passwords: Whether to capture passwords (use carefully)
        """
        page_id = str(uuid.uuid4())

        page = {
            'id': page_id,
            'name': name,
            'html': html,
            'capture_credentials': capture_credentials,
            'capture_passwords': capture_passwords,
            'created_at': datetime.utcnow().isoformat()
        }

        self.landing_pages[page_id] = page
        print(f"[Gophish] Created landing page: {name}")

        return page_id

    def clone_website(self, url: str, name: str) -> str:
        """
        Clone website for landing page

        Args:
            url: URL to clone
            name: Name for cloned page
        """
        print(f"[Gophish] Cloning website: {url}")

        # In production: fetch and clone website
        html = f"<!-- Cloned from {url} -->"

        return self.create_landing_page(name, html)

    def create_campaign(
        self,
        name: str,
        template_id: str,
        landing_page_id: str,
        targets: List[Dict],
        smtp_config: Optional[Dict] = None
    ) -> PhishingCampaign:
        """
        Create phishing campaign

        Args:
            name: Campaign name
            template_id: Email template ID
            landing_page_id: Landing page ID
            targets: List of targets (email, first_name, last_name, position)
            smtp_config: SMTP configuration
        """
        campaign_id = str(uuid.uuid4())

        campaign = PhishingCampaign(
            campaign_id, name, template_id, landing_page_id, targets
        )

        self.campaigns[campaign_id] = campaign
        print(f"[Gophish] Created campaign: {name} ({len(targets)} targets)")

        return campaign

    def launch_campaign(self, campaign_id: str) -> Dict:
        """
        Launch phishing campaign

        Args:
            campaign_id: Campaign ID
        """
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        campaign.status = 'running'

        print(f"[Gophish] Launching campaign: {campaign.name}")

        return {
            'campaign_id': campaign_id,
            'status': 'launched',
            'targets': len(campaign.targets)
        }

    def get_campaign_results(self, campaign_id: str) -> Dict:
        """
        Get campaign results

        Args:
            campaign_id: Campaign ID
        """
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]

        # Calculate statistics
        total = len(campaign.targets)
        opened = len([r for r in campaign.results.values() if r.get('opened')])
        clicked = len([r for r in campaign.results.values() if r.get('clicked')])
        submitted = len([r for r in campaign.results.values() if r.get('submitted_data')])

        return {
            'campaign_id': campaign_id,
            'name': campaign.name,
            'status': campaign.status,
            'statistics': {
                'total_targets': total,
                'emails_sent': total,
                'emails_opened': opened,
                'links_clicked': clicked,
                'credentials_submitted': submitted,
                'open_rate': f"{(opened/total*100) if total > 0 else 0:.1f}%",
                'click_rate': f"{(clicked/total*100) if total > 0 else 0:.1f}%",
                'submission_rate': f"{(submitted/total*100) if total > 0 else 0:.1f}%"
            },
            'results': campaign.results
        }

    def stop_campaign(self, campaign_id: str) -> bool:
        """Stop running campaign"""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].status = 'stopped'
            print(f"[Gophish] Stopped campaign {campaign_id}")
            return True
        return False

    def get_harvested_credentials(self, campaign_id: str) -> List[Dict]:
        """
        Get harvested credentials (AUTHORIZED ONLY)

        Args:
            campaign_id: Campaign ID
        """
        if campaign_id not in self.campaigns:
            return []

        campaign = self.campaigns[campaign_id]

        credentials = []
        for target_email, result in campaign.results.items():
            if result.get('submitted_data'):
                credentials.append({
                    'email': target_email,
                    'data': result['submitted_data'],
                    'timestamp': result.get('submission_time')
                })

        return credentials

    def generate_campaign_report(self, campaign_id: str) -> Dict:
        """Generate comprehensive campaign report"""
        results = self.get_campaign_results(campaign_id)

        return {
            **results,
            'report_generated': datetime.utcnow().isoformat(),
            'recommendations': self._generate_recommendations(results)
        }

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on results"""
        recommendations = []

        stats = results.get('statistics', {})
        click_rate = float(stats.get('click_rate', '0').rstrip('%'))

        if click_rate > 50:
            recommendations.append("HIGH RISK: Over 50% click rate indicates need for security awareness training")
        elif click_rate > 25:
            recommendations.append("MEDIUM RISK: Click rate suggests targeted security training needed")

        return recommendations

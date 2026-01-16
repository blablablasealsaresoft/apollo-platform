"""
Email Header Analyzer - Parse and analyze email headers
IP extraction, routing analysis, authentication checks
"""

import re
import email
from email import policy
from email.parser import Parser
from typing import Dict, List, Optional, Any, Tuple
import logging
from datetime import datetime
from dataclasses import dataclass
import socket
import dns.resolver
import json


@dataclass
class EmailHeader:
    """Parsed email header information"""
    from_address: str
    to_addresses: List[str]
    subject: str
    date: Optional[str]
    message_id: Optional[str]
    return_path: Optional[str]
    received_headers: List[Dict[str, Any]]
    ip_addresses: List[str]
    domains: List[str]
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]
    authentication_results: Dict[str, Any]
    route_analysis: List[Dict[str, Any]]
    suspicious_indicators: List[str]


class EmailHeaderAnalyzer:
    """
    Email header analysis system
    Parses headers, extracts IPs, analyzes routing, checks authentication
    """

    def __init__(self):
        """Initialize Email Header Analyzer"""
        self.logger = self._setup_logging()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailHeaderAnalyzer')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def analyze(self, headers: str) -> Dict[str, Any]:
        """
        Analyze email headers

        Args:
            headers: Raw email headers

        Returns:
            Analysis results
        """
        try:
            # Parse headers
            msg = Parser(policy=policy.default).parsestr(headers)

            # Extract basic information
            from_address = self._extract_email(msg.get('From', ''))
            to_addresses = self._extract_emails(msg.get('To', ''))
            subject = msg.get('Subject', '')
            date = msg.get('Date')
            message_id = msg.get('Message-ID')
            return_path = msg.get('Return-Path')

            # Parse Received headers
            received_headers = self._parse_received_headers(msg.get_all('Received', []))

            # Extract IPs and domains
            ip_addresses = self._extract_ips(received_headers)
            domains = self._extract_domains(received_headers)

            # Authentication results
            spf_result = self._extract_spf_result(msg)
            dkim_result = self._extract_dkim_result(msg)
            dmarc_result = self._extract_dmarc_result(msg)
            auth_results = self._parse_authentication_results(msg)

            # Route analysis
            route_analysis = self._analyze_route(received_headers, ip_addresses)

            # Suspicious indicators
            suspicious = self._check_suspicious_indicators(
                msg, from_address, received_headers, auth_results
            )

            return {
                'from_address': from_address,
                'to_addresses': to_addresses,
                'subject': subject,
                'date': date,
                'message_id': message_id,
                'return_path': return_path,
                'received_headers': received_headers,
                'ip_addresses': ip_addresses,
                'domains': domains,
                'spf_result': spf_result,
                'dkim_result': dkim_result,
                'dmarc_result': dmarc_result,
                'authentication_results': auth_results,
                'route_analysis': route_analysis,
                'suspicious_indicators': suspicious,
                'hop_count': len(received_headers),
                'analysis_timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Header analysis error: {str(e)}")
            return {'error': str(e)}

    def _extract_email(self, email_str: str) -> str:
        """Extract email address from header string"""
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', email_str)
        return match.group(0) if match else email_str

    def _extract_emails(self, email_str: str) -> List[str]:
        """Extract multiple email addresses"""
        return re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', email_str)

    def _parse_received_headers(self, received_list: List[str]) -> List[Dict[str, Any]]:
        """
        Parse Received headers

        Args:
            received_list: List of Received header values

        Returns:
            List of parsed Received headers
        """
        parsed = []

        for received in received_list:
            parsed_header = {
                'raw': received,
                'from': self._extract_received_from(received),
                'by': self._extract_received_by(received),
                'with': self._extract_received_with(received),
                'id': self._extract_received_id(received),
                'for': self._extract_received_for(received),
                'date': self._extract_received_date(received),
                'ip': self._extract_received_ip(received)
            }
            parsed.append(parsed_header)

        return parsed

    def _extract_received_from(self, received: str) -> Optional[str]:
        """Extract 'from' field from Received header"""
        match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_received_by(self, received: str) -> Optional[str]:
        """Extract 'by' field from Received header"""
        match = re.search(r'by\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_received_with(self, received: str) -> Optional[str]:
        """Extract 'with' field from Received header"""
        match = re.search(r'with\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_received_id(self, received: str) -> Optional[str]:
        """Extract 'id' field from Received header"""
        match = re.search(r'id\s+([^\s;]+)', received, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_received_for(self, received: str) -> Optional[str]:
        """Extract 'for' field from Received header"""
        match = re.search(r'for\s+<([^>]+)>', received, re.IGNORECASE)
        if not match:
            match = re.search(r'for\s+([^\s;]+)', received, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_received_date(self, received: str) -> Optional[str]:
        """Extract date from Received header"""
        match = re.search(r';\s*(.+)$', received)
        return match.group(1).strip() if match else None

    def _extract_received_ip(self, received: str) -> Optional[str]:
        """Extract IP address from Received header"""
        # Look for IP in brackets
        match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
        if match:
            return match.group(1)

        # Look for IP without brackets
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', received)
        return match.group(1) if match else None

    def _extract_ips(self, received_headers: List[Dict[str, Any]]) -> List[str]:
        """Extract all IP addresses from received headers"""
        ips = []
        for header in received_headers:
            if header.get('ip'):
                ips.append(header['ip'])
        return list(set(ips))  # Remove duplicates

    def _extract_domains(self, received_headers: List[Dict[str, Any]]) -> List[str]:
        """Extract all domains from received headers"""
        domains = []
        for header in received_headers:
            if header.get('from'):
                domain = self._extract_domain_from_host(header['from'])
                if domain:
                    domains.append(domain)
            if header.get('by'):
                domain = self._extract_domain_from_host(header['by'])
                if domain:
                    domains.append(domain)
        return list(set(domains))  # Remove duplicates

    def _extract_domain_from_host(self, host: str) -> Optional[str]:
        """Extract domain from hostname"""
        # Remove IP addresses and brackets
        host = re.sub(r'\[.*?\]', '', host)
        # Extract domain-like pattern
        match = re.search(r'([\w-]+\.)+[\w-]+', host)
        return match.group(0) if match else None

    def _extract_spf_result(self, msg: email.message.EmailMessage) -> Optional[str]:
        """Extract SPF result from headers"""
        received_spf = msg.get('Received-SPF', '')
        if received_spf:
            match = re.search(r'^(\w+)', received_spf, re.IGNORECASE)
            return match.group(1) if match else None

        auth_results = msg.get('Authentication-Results', '')
        if 'spf=' in auth_results.lower():
            match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            return match.group(1) if match else None

        return None

    def _extract_dkim_result(self, msg: email.message.EmailMessage) -> Optional[str]:
        """Extract DKIM result from headers"""
        auth_results = msg.get('Authentication-Results', '')
        if 'dkim=' in auth_results.lower():
            match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            return match.group(1) if match else None

        dkim_signature = msg.get('DKIM-Signature')
        return 'present' if dkim_signature else None

    def _extract_dmarc_result(self, msg: email.message.EmailMessage) -> Optional[str]:
        """Extract DMARC result from headers"""
        auth_results = msg.get('Authentication-Results', '')
        if 'dmarc=' in auth_results.lower():
            match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            return match.group(1) if match else None

        return None

    def _parse_authentication_results(self, msg: email.message.EmailMessage) -> Dict[str, Any]:
        """Parse Authentication-Results header"""
        auth_results = msg.get('Authentication-Results', '')

        results = {
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'raw': auth_results
        }

        if auth_results:
            # Parse SPF
            spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_match:
                results['spf'] = spf_match.group(1)

            # Parse DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_match:
                results['dkim'] = dkim_match.group(1)

            # Parse DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                results['dmarc'] = dmarc_match.group(1)

        return results

    def _analyze_route(self, received_headers: List[Dict[str, Any]], ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze email routing path

        Args:
            received_headers: Parsed Received headers
            ip_addresses: Extracted IP addresses

        Returns:
            List of route hops with analysis
        """
        route = []

        for i, (header, ip) in enumerate(zip(received_headers, ip_addresses)):
            hop = {
                'hop_number': i + 1,
                'ip': ip,
                'hostname': header.get('from'),
                'timestamp': header.get('date'),
                'geo_location': self._geolocate_ip(ip),
                'reverse_dns': self._reverse_dns_lookup(ip),
                'is_relay': self._is_relay_server(header),
                'protocol': header.get('with')
            }
            route.append(hop)

        return route

    def _geolocate_ip(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Geolocate IP address

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        # This is a placeholder for IP geolocation
        # In production, integrate with services like MaxMind, IPinfo, etc.
        return {
            'ip': ip,
            'country': 'Unknown',
            'city': 'Unknown',
            'asn': 'Unknown'
        }

    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address

        Returns:
            Hostname or None
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def _is_relay_server(self, header: Dict[str, Any]) -> bool:
        """Check if server is a relay"""
        protocol = header.get('with', '').lower()
        return 'smtp' in protocol or 'relay' in protocol

    def _check_suspicious_indicators(self,
                                    msg: email.message.EmailMessage,
                                    from_address: str,
                                    received_headers: List[Dict[str, Any]],
                                    auth_results: Dict[str, Any]) -> List[str]:
        """
        Check for suspicious indicators

        Args:
            msg: Email message
            from_address: From address
            received_headers: Received headers
            auth_results: Authentication results

        Returns:
            List of suspicious indicators
        """
        indicators = []

        # Authentication failures
        if auth_results.get('spf') in ['fail', 'softfail', 'none']:
            indicators.append(f"SPF check failed: {auth_results.get('spf')}")

        if auth_results.get('dkim') in ['fail', 'none']:
            indicators.append(f"DKIM check failed: {auth_results.get('dkim')}")

        if auth_results.get('dmarc') in ['fail', 'none']:
            indicators.append(f"DMARC check failed: {auth_results.get('dmarc')}")

        # Return-Path mismatch
        return_path = msg.get('Return-Path', '')
        if return_path and from_address:
            return_email = self._extract_email(return_path)
            if return_email and return_email != from_address:
                from_domain = from_address.split('@')[1] if '@' in from_address else ''
                return_domain = return_email.split('@')[1] if '@' in return_email else ''
                if from_domain != return_domain:
                    indicators.append(f"Return-Path domain mismatch: {return_domain} vs {from_domain}")

        # Suspicious hop count
        if len(received_headers) > 15:
            indicators.append(f"Excessive hop count: {len(received_headers)}")

        # Missing headers
        if not msg.get('Message-ID'):
            indicators.append("Missing Message-ID header")

        # Suspicious subject patterns
        subject = msg.get('Subject', '').lower()
        suspicious_keywords = ['urgent', 'verify', 'suspended', 'confirm', 'password', 'account']
        if any(keyword in subject for keyword in suspicious_keywords):
            indicators.append(f"Suspicious subject keywords")

        return indicators

    def export_analysis(self, analysis: Dict[str, Any], format: str = 'json') -> str:
        """
        Export analysis results

        Args:
            analysis: Analysis results
            format: Export format (json, text)

        Returns:
            Exported data
        """
        if format == 'json':
            return json.dumps(analysis, indent=2)
        elif format == 'text':
            return self._format_text_report(analysis)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _format_text_report(self, analysis: Dict[str, Any]) -> str:
        """Format analysis as text report"""
        report = []
        report.append("=" * 70)
        report.append("EMAIL HEADER ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"\nFrom: {analysis.get('from_address')}")
        report.append(f"To: {', '.join(analysis.get('to_addresses', []))}")
        report.append(f"Subject: {analysis.get('subject')}")
        report.append(f"Date: {analysis.get('date')}")
        report.append(f"\nMessage-ID: {analysis.get('message_id')}")
        report.append(f"Return-Path: {analysis.get('return_path')}")

        report.append(f"\n{'='*70}")
        report.append("AUTHENTICATION RESULTS")
        report.append("=" * 70)
        report.append(f"SPF: {analysis.get('spf_result', 'Not found')}")
        report.append(f"DKIM: {analysis.get('dkim_result', 'Not found')}")
        report.append(f"DMARC: {analysis.get('dmarc_result', 'Not found')}")

        report.append(f"\n{'='*70}")
        report.append("ROUTING INFORMATION")
        report.append("=" * 70)
        report.append(f"Total Hops: {analysis.get('hop_count', 0)}")
        report.append(f"IP Addresses: {', '.join(analysis.get('ip_addresses', []))}")

        if analysis.get('suspicious_indicators'):
            report.append(f"\n{'='*70}")
            report.append("SUSPICIOUS INDICATORS")
            report.append("=" * 70)
            for indicator in analysis['suspicious_indicators']:
                report.append(f"- {indicator}")

        return '\n'.join(report)


if __name__ == "__main__":
    # Example usage
    analyzer = EmailHeaderAnalyzer()

    sample_headers = """
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 14 Jan 2026 10:00:00 +0000
Message-ID: <12345@example.com>
Received: from mail.example.com ([192.0.2.1])
    by mx.google.com with ESMTP id abc123
    for <recipient@example.com>; Mon, 14 Jan 2026 10:00:00 +0000
    """

    analysis = analyzer.analyze(sample_headers)
    print(json.dumps(analysis, indent=2))

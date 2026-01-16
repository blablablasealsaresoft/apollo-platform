"""
Email Format Finder - Company email pattern detection
Generate employee emails based on company patterns
"""

import re
import requests
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
from collections import Counter
import json


@dataclass
class EmailFormat:
    """Email format pattern"""
    pattern: str
    confidence: float
    sample_count: int
    examples: List[str]
    domain: str


class EmailFormatFinder:
    """
    Email format detection and generation system
    Identifies company email patterns and generates employee emails
    """

    # Common email patterns with descriptions
    PATTERNS = {
        '{first}.{last}': 'First name + dot + Last name (john.doe)',
        '{first}{last}': 'First name + Last name (johndoe)',
        '{f}{last}': 'First initial + Last name (jdoe)',
        '{first}': 'First name only (john)',
        '{last}': 'Last name only (doe)',
        '{first}.{l}': 'First name + dot + Last initial (john.d)',
        '{first}_{last}': 'First name + underscore + Last name (john_doe)',
        '{f}.{last}': 'First initial + dot + Last name (j.doe)',
        '{last}.{first}': 'Last name + dot + First name (doe.john)',
        '{last}{first}': 'Last name + First name (doejohn)',
        '{last}{f}': 'Last name + First initial (doej)',
        '{f}{l}': 'First initial + Last initial (jd)',
        '{first}{l}': 'First name + Last initial (johnd)'
    }

    def __init__(self):
        """Initialize Email Format Finder"""
        self.logger = self._setup_logging()
        self.cache = {}

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailFormatFinder')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def detect_pattern(self, emails: List[str]) -> Optional[EmailFormat]:
        """
        Detect email pattern from sample emails

        Args:
            emails: List of sample emails from same domain

        Returns:
            EmailFormat with detected pattern
        """
        if not emails:
            return None

        # Extract domain
        domain = emails[0].split('@')[1] if '@' in emails[0] else ''

        # Try to detect pattern from emails
        pattern_matches = Counter()

        for email in emails:
            if '@' not in email:
                continue

            local_part = email.split('@')[0].lower()

            # Try to match against known patterns
            detected = self._match_pattern(local_part)
            if detected:
                pattern_matches[detected] += 1

        if not pattern_matches:
            return None

        # Get most common pattern
        best_pattern, count = pattern_matches.most_common(1)[0]
        confidence = count / len(emails)

        return EmailFormat(
            pattern=best_pattern,
            confidence=confidence,
            sample_count=len(emails),
            examples=emails[:3],
            domain=domain
        )

    def _match_pattern(self, local_part: str) -> Optional[str]:
        """
        Try to match local part against known patterns

        Args:
            local_part: Local part of email

        Returns:
            Matched pattern or None
        """
        # Common separators
        if '.' in local_part:
            parts = local_part.split('.')
            if len(parts) == 2:
                if len(parts[0]) > 1 and len(parts[1]) > 1:
                    return '{first}.{last}'
                elif len(parts[0]) == 1 and len(parts[1]) > 1:
                    return '{f}.{last}'
                elif len(parts[0]) > 1 and len(parts[1]) == 1:
                    return '{first}.{l}'

        if '_' in local_part:
            parts = local_part.split('_')
            if len(parts) == 2 and len(parts[0]) > 1 and len(parts[1]) > 1:
                return '{first}_{last}'

        # Check for combined names
        if len(local_part) > 3:
            # Could be firstname + lastname or variations
            return '{first}{last}'

        return None

    def generate_email(self,
                      first_name: str,
                      last_name: str,
                      domain: str,
                      pattern: str) -> str:
        """
        Generate email based on pattern

        Args:
            first_name: First name
            last_name: Last name
            domain: Email domain
            pattern: Email pattern

        Returns:
            Generated email address
        """
        first = first_name.lower().strip()
        last = last_name.lower().strip()

        email_local = pattern
        email_local = email_local.replace('{first}', first)
        email_local = email_local.replace('{last}', last)
        email_local = email_local.replace('{f}', first[0] if first else '')
        email_local = email_local.replace('{l}', last[0] if last else '')

        return f"{email_local}@{domain}"

    def generate_emails(self,
                       domain: str,
                       pattern: Optional[str] = None,
                       names: Optional[List[Tuple[str, str]]] = None) -> List[str]:
        """
        Generate multiple emails for a domain

        Args:
            domain: Email domain
            pattern: Email pattern (if None, use all common patterns)
            names: List of (first_name, last_name) tuples

        Returns:
            List of generated emails
        """
        if not names:
            # Use sample names for testing
            names = [
                ('John', 'Doe'),
                ('Jane', 'Smith'),
                ('Robert', 'Johnson')
            ]

        emails = []

        if pattern:
            patterns_to_use = [pattern]
        else:
            patterns_to_use = list(self.PATTERNS.keys())

        for first_name, last_name in names:
            for pat in patterns_to_use:
                try:
                    email = self.generate_email(first_name, last_name, domain, pat)
                    emails.append(email)
                except Exception as e:
                    self.logger.debug(f"Error generating email with pattern {pat}: {str(e)}")

        return emails

    def generate_all_variations(self,
                               first_name: str,
                               last_name: str,
                               domain: str) -> List[Dict[str, str]]:
        """
        Generate all possible email variations

        Args:
            first_name: First name
            last_name: Last name
            domain: Email domain

        Returns:
            List of email variations with patterns
        """
        variations = []

        for pattern, description in self.PATTERNS.items():
            try:
                email = self.generate_email(first_name, last_name, domain, pattern)
                variations.append({
                    'email': email,
                    'pattern': pattern,
                    'description': description
                })
            except Exception as e:
                self.logger.debug(f"Error generating variation {pattern}: {str(e)}")

        return variations

    def guess_pattern(self, domain: str) -> EmailFormat:
        """
        Guess most likely pattern for domain

        Args:
            domain: Email domain

        Returns:
            EmailFormat with guessed pattern
        """
        # Check cache
        if domain in self.cache:
            return self.cache[domain]

        # Try to find known pattern from common sources
        known_pattern = self._lookup_known_pattern(domain)

        if known_pattern:
            format_obj = EmailFormat(
                pattern=known_pattern,
                confidence=0.7,
                sample_count=0,
                examples=[],
                domain=domain
            )
        else:
            # Default to most common pattern
            format_obj = EmailFormat(
                pattern='{first}.{last}',
                confidence=0.5,
                sample_count=0,
                examples=[],
                domain=domain
            )

        self.cache[domain] = format_obj
        return format_obj

    def _lookup_known_pattern(self, domain: str) -> Optional[str]:
        """
        Look up known pattern for domain

        Args:
            domain: Email domain

        Returns:
            Known pattern or None
        """
        # Common patterns for known companies
        known_patterns = {
            'gmail.com': '{first}.{last}',
            'google.com': '{first}',
            'microsoft.com': '{first}{last}',
            'apple.com': '{first}{last}',
            'amazon.com': '{first}',
            'facebook.com': '{first}{last}',
            'linkedin.com': '{first}{last}',
            'twitter.com': '{first}{last}',
            'ibm.com': '{first}.{last}',
            'oracle.com': '{first}.{last}',
            'salesforce.com': '{first}.{last}',
        }

        return known_patterns.get(domain.lower())

    def validate_pattern(self, pattern: str) -> bool:
        """
        Validate if pattern is supported

        Args:
            pattern: Pattern to validate

        Returns:
            True if pattern is valid
        """
        return pattern in self.PATTERNS

    def get_pattern_description(self, pattern: str) -> str:
        """
        Get description for pattern

        Args:
            pattern: Pattern string

        Returns:
            Pattern description
        """
        return self.PATTERNS.get(pattern, 'Unknown pattern')

    def get_all_patterns(self) -> Dict[str, str]:
        """
        Get all supported patterns

        Returns:
            Dictionary of patterns and descriptions
        """
        return self.PATTERNS.copy()

    def suggest_patterns(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        Suggest possible patterns based on sample emails

        Args:
            emails: Sample emails

        Returns:
            List of suggested patterns with confidence scores
        """
        suggestions = []
        domain = emails[0].split('@')[1] if emails and '@' in emails[0] else ''

        pattern_scores = Counter()

        for email in emails:
            if '@' not in email:
                continue

            local_part = email.split('@')[0].lower()
            detected = self._match_pattern(local_part)

            if detected:
                pattern_scores[detected] += 1

        total = len(emails)

        for pattern, count in pattern_scores.most_common():
            suggestions.append({
                'pattern': pattern,
                'description': self.PATTERNS.get(pattern, 'Unknown'),
                'confidence': count / total if total > 0 else 0,
                'matches': count,
                'example': self.generate_email('John', 'Doe', domain, pattern)
            })

        return suggestions

    def find_pattern_from_linkedin(self, company_name: str, linkedin_urls: List[str]) -> Optional[EmailFormat]:
        """
        Find email pattern by analyzing LinkedIn profiles

        Args:
            company_name: Company name
            linkedin_urls: List of employee LinkedIn URLs

        Returns:
            EmailFormat or None
        """
        # This is a placeholder for LinkedIn integration
        # In production, this would scrape LinkedIn profiles to find email patterns
        self.logger.info(f"LinkedIn pattern detection not implemented for {company_name}")
        return None

    def export_patterns(self, filepath: str) -> None:
        """
        Export cached patterns to file

        Args:
            filepath: Output file path
        """
        try:
            data = {
                domain: {
                    'pattern': fmt.pattern,
                    'confidence': fmt.confidence,
                    'sample_count': fmt.sample_count,
                    'examples': fmt.examples
                }
                for domain, fmt in self.cache.items()
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            self.logger.info(f"Exported {len(data)} patterns to {filepath}")

        except Exception as e:
            self.logger.error(f"Failed to export patterns: {str(e)}")

    def import_patterns(self, filepath: str) -> None:
        """
        Import patterns from file

        Args:
            filepath: Input file path
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            for domain, pattern_data in data.items():
                self.cache[domain] = EmailFormat(
                    pattern=pattern_data['pattern'],
                    confidence=pattern_data['confidence'],
                    sample_count=pattern_data['sample_count'],
                    examples=pattern_data.get('examples', []),
                    domain=domain
                )

            self.logger.info(f"Imported {len(data)} patterns from {filepath}")

        except Exception as e:
            self.logger.error(f"Failed to import patterns: {str(e)}")


class PermutationGenerator:
    """
    Generate email permutations for testing
    """

    @staticmethod
    def generate_permutations(first_name: str,
                             last_name: str,
                             domain: str,
                             include_numbers: bool = False,
                             include_separators: bool = True) -> List[str]:
        """
        Generate all possible email permutations

        Args:
            first_name: First name
            last_name: Last name
            domain: Email domain
            include_numbers: Include numbered variations
            include_separators: Include separator variations

        Returns:
            List of email permutations
        """
        first = first_name.lower().strip()
        last = last_name.lower().strip()
        f = first[0] if first else ''
        l = last[0] if last else ''

        permutations = []

        # Basic combinations
        basic = [
            f"{first}.{last}",
            f"{first}{last}",
            f"{f}{last}",
            f"{first}.{l}",
            f"{first}_{last}",
            f"{f}.{last}",
            f"{last}.{first}",
            f"{last}{first}",
            f"{last}{f}",
            f"{f}{l}",
            f"{first}{l}",
            f"{first}",
            f"{last}",
        ]

        permutations.extend(basic)

        # Add separator variations
        if include_separators:
            separators = ['-', '_']
            for sep in separators:
                permutations.extend([
                    f"{first}{sep}{last}",
                    f"{last}{sep}{first}",
                    f"{f}{sep}{last}",
                    f"{first}{sep}{l}"
                ])

        # Add numbered variations
        if include_numbers:
            for i in range(1, 10):
                permutations.extend([
                    f"{first}.{last}{i}",
                    f"{first}{last}{i}",
                    f"{first}{i}",
                    f"{last}{i}"
                ])

        # Create full emails
        emails = [f"{p}@{domain}" for p in permutations if p]

        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in emails:
            if email not in seen:
                seen.add(email)
                unique_emails.append(email)

        return unique_emails


if __name__ == "__main__":
    # Example usage
    finder = EmailFormatFinder()

    # Detect pattern from samples
    sample_emails = [
        "john.doe@company.com",
        "jane.smith@company.com",
        "bob.johnson@company.com"
    ]

    pattern = finder.detect_pattern(sample_emails)
    if pattern:
        print(f"Detected pattern: {pattern.pattern}")
        print(f"Confidence: {pattern.confidence:.2%}")

    # Generate email variations
    variations = finder.generate_all_variations("John", "Doe", "company.com")
    for var in variations:
        print(f"{var['email']} - {var['description']}")

    # Generate permutations
    gen = PermutationGenerator()
    perms = gen.generate_permutations("John", "Doe", "company.com")
    print(f"\nGenerated {len(perms)} permutations")

"""
Credential Intelligence Analyzer
Analyze credentials for patterns, security, and intelligence extraction
"""

import re
import logging
from typing import Dict, List, Optional, Set, Any
from collections import Counter, defaultdict
import string
import hashlib
from datetime import datetime


class CredentialAnalyzer:
    """
    Credential intelligence analyzer
    Extract patterns, security insights, and personal information
    """

    def __init__(self):
        """Initialize credential analyzer"""
        self.logger = logging.getLogger(__name__)

        # Common weak passwords
        self.weak_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football'
        }

        # Common password patterns
        self.patterns = {
            'year': re.compile(r'(19|20)\d{2}'),
            'sequential': re.compile(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)'),
            'keyboard': re.compile(r'(qwerty|asdfgh|zxcvbn)'),
            'repeated': re.compile(r'(.)\1{2,}'),
            'name_like': re.compile(r'^[A-Z][a-z]+\d*$'),
            'phone': re.compile(r'\d{3}[-.]?\d{3}[-.]?\d{4}'),
            'date': re.compile(r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}'),
            'email_in_password': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        }

        # Security question keywords
        self.security_keywords = {
            'mother', 'father', 'pet', 'school', 'city', 'street',
            'car', 'teacher', 'friend', 'color', 'food', 'maiden'
        }

    def analyze_credentials(self, records: List[Any]) -> Dict[str, Any]:
        """
        Comprehensive credential analysis

        Args:
            records: List of breach records

        Returns:
            Analysis results
        """
        self.logger.info(f"Analyzing credentials from {len(records)} records")

        if not records:
            return {}

        passwords = [r.password for r in records if r.password]

        return {
            'password_analysis': self._analyze_passwords(passwords),
            'pattern_analysis': self._analyze_patterns(passwords),
            'security_analysis': self._analyze_security(passwords),
            'personal_info': self._extract_personal_info(records),
            'intelligence': self._extract_intelligence(records),
            'recommendations': self._generate_recommendations(passwords, records)
        }

    def _analyze_passwords(self, passwords: List[str]) -> Dict[str, Any]:
        """
        Analyze password characteristics

        Args:
            passwords: List of passwords

        Returns:
            Password analysis
        """
        if not passwords:
            return {}

        total = len(passwords)
        unique = len(set(passwords))

        # Length analysis
        lengths = [len(p) for p in passwords]
        avg_length = sum(lengths) / len(lengths)
        min_length = min(lengths)
        max_length = max(lengths)

        # Character composition
        has_upper = sum(1 for p in passwords if any(c.isupper() for c in p))
        has_lower = sum(1 for p in passwords if any(c.islower() for c in p))
        has_digit = sum(1 for p in passwords if any(c.isdigit() for c in p))
        has_special = sum(1 for p in passwords if any(c in string.punctuation for c in p))

        # Common passwords
        common_count = sum(1 for p in passwords if p.lower() in self.weak_passwords)

        # Entropy calculation
        entropies = [self._calculate_entropy(p) for p in passwords]
        avg_entropy = sum(entropies) / len(entropies)

        return {
            'total_passwords': total,
            'unique_passwords': unique,
            'uniqueness_ratio': unique / total if total > 0 else 0,
            'length_stats': {
                'average': avg_length,
                'minimum': min_length,
                'maximum': max_length
            },
            'composition': {
                'with_uppercase': has_upper,
                'with_lowercase': has_lower,
                'with_digits': has_digit,
                'with_special': has_special,
                'percentage_uppercase': (has_upper / total * 100) if total > 0 else 0,
                'percentage_lowercase': (has_lower / total * 100) if total > 0 else 0,
                'percentage_digits': (has_digit / total * 100) if total > 0 else 0,
                'percentage_special': (has_special / total * 100) if total > 0 else 0
            },
            'common_passwords': common_count,
            'common_percentage': (common_count / total * 100) if total > 0 else 0,
            'average_entropy': avg_entropy,
            'most_common': [
                {'password': pwd, 'count': count}
                for pwd, count in Counter(passwords).most_common(10)
            ]
        }

    def _analyze_patterns(self, passwords: List[str]) -> Dict[str, Any]:
        """
        Analyze password patterns

        Args:
            passwords: List of passwords

        Returns:
            Pattern analysis
        """
        if not passwords:
            return {}

        pattern_matches = defaultdict(list)

        for password in passwords:
            for pattern_name, pattern_regex in self.patterns.items():
                if pattern_regex.search(password.lower()):
                    pattern_matches[pattern_name].append(password)

        # Analyze specific patterns
        years = []
        for password in passwords:
            year_match = self.patterns['year'].search(password)
            if year_match:
                years.append(int(year_match.group()))

        # Common base words
        base_words = self._extract_base_words(passwords)

        # Numbering patterns (password1, password2, etc.)
        numbering_patterns = self._find_numbering_patterns(passwords)

        return {
            'pattern_counts': {
                pattern: len(matches)
                for pattern, matches in pattern_matches.items()
            },
            'years_found': {
                'unique_years': list(set(years)),
                'year_range': f"{min(years)}-{max(years)}" if years else None,
                'most_common_years': [
                    {'year': year, 'count': count}
                    for year, count in Counter(years).most_common(5)
                ]
            } if years else {},
            'base_words': base_words[:20],
            'numbering_patterns': numbering_patterns,
            'keyboard_walks': len(pattern_matches['keyboard']),
            'sequential_chars': len(pattern_matches['sequential'])
        }

    def _analyze_security(self, passwords: List[str]) -> Dict[str, Any]:
        """
        Analyze password security

        Args:
            passwords: List of passwords

        Returns:
            Security analysis
        """
        if not passwords:
            return {}

        total = len(passwords)

        # Strength classification
        strength_counts = {
            'very_weak': 0,
            'weak': 0,
            'medium': 0,
            'strong': 0,
            'very_strong': 0
        }

        for password in passwords:
            strength = self._calculate_strength(password)
            strength_counts[strength] += 1

        # Crackability assessment
        crackability = {
            'instant': 0,  # < 8 chars, no complexity
            'minutes': 0,  # 8 chars, low complexity
            'hours': 0,    # 8-10 chars, medium complexity
            'days': 0,     # 10-12 chars, good complexity
            'months': 0,   # 12-14 chars, high complexity
            'years': 0     # 14+ chars, high complexity
        }

        for password in passwords:
            crack_time = self._estimate_crack_time(password)
            crackability[crack_time] += 1

        return {
            'strength_distribution': strength_counts,
            'strength_percentages': {
                level: (count / total * 100) if total > 0 else 0
                for level, count in strength_counts.items()
            },
            'crackability': crackability,
            'crackability_percentages': {
                level: (count / total * 100) if total > 0 else 0
                for level, count in crackability.items()
            },
            'average_score': self._calculate_average_security_score(passwords)
        }

    def _extract_personal_info(self, records: List[Any]) -> Dict[str, Any]:
        """
        Extract personal information from credentials

        Args:
            records: Breach records

        Returns:
            Personal information
        """
        personal_info = {
            'names': set(),
            'potential_names': set(),
            'years': set(),
            'locations': set(),
            'phone_numbers': set(),
            'security_answers': []
        }

        for record in records:
            # Extract from name field
            if record.name:
                personal_info['names'].add(record.name)

            # Extract from username
            if record.username:
                # Check if username contains name-like patterns
                if self.patterns['name_like'].match(record.username):
                    personal_info['potential_names'].add(record.username)

            # Extract from password
            if record.password:
                # Look for years
                year_matches = self.patterns['year'].findall(record.password)
                personal_info['years'].update(year_matches)

                # Look for phone numbers
                phone_matches = self.patterns['phone'].findall(record.password)
                personal_info['phone_numbers'].update(phone_matches)

                # Look for potential security question answers
                pwd_lower = record.password.lower()
                for keyword in self.security_keywords:
                    if keyword in pwd_lower:
                        personal_info['security_answers'].append({
                            'password': record.password,
                            'keyword': keyword,
                            'email': record.email
                        })

        return {
            'names': list(personal_info['names']),
            'potential_names': list(personal_info['potential_names'])[:20],
            'years': sorted(list(personal_info['years'])),
            'phone_numbers': list(personal_info['phone_numbers']),
            'security_answers': personal_info['security_answers'][:20]
        }

    def _extract_intelligence(self, records: List[Any]) -> Dict[str, Any]:
        """
        Extract actionable intelligence

        Args:
            records: Breach records

        Returns:
            Intelligence data
        """
        intelligence = {
            'password_mutations': self._find_password_mutations(records),
            'username_conventions': self._analyze_username_conventions(records),
            'email_domains': self._analyze_email_domains(records),
            'credential_patterns': self._find_credential_patterns(records)
        }

        return intelligence

    def _find_password_mutations(self, records: List[Any]) -> List[Dict[str, Any]]:
        """Find password mutations (e.g., password1, password2)"""
        passwords = [r.password for r in records if r.password]

        mutations = []
        password_bases = defaultdict(list)

        for password in passwords:
            # Remove trailing digits
            base = re.sub(r'\d+$', '', password)
            if base and base != password:
                password_bases[base].append(password)

        for base, variants in password_bases.items():
            if len(variants) > 1:
                mutations.append({
                    'base': base,
                    'variants': variants,
                    'count': len(variants)
                })

        return sorted(mutations, key=lambda x: x['count'], reverse=True)[:10]

    def _analyze_username_conventions(self, records: List[Any]) -> Dict[str, Any]:
        """Analyze username conventions"""
        usernames = [r.username for r in records if r.username]

        if not usernames:
            return {}

        # Analyze formats
        formats = {
            'email_format': sum(1 for u in usernames if '@' in u),
            'dot_separated': sum(1 for u in usernames if '.' in u),
            'underscore_separated': sum(1 for u in usernames if '_' in u),
            'hyphen_separated': sum(1 for u in usernames if '-' in u),
            'numeric_suffix': sum(1 for u in usernames if u[-1].isdigit()),
            'all_lowercase': sum(1 for u in usernames if u.islower()),
            'mixed_case': sum(1 for u in usernames if not u.islower() and not u.isupper())
        }

        return {
            'total_usernames': len(usernames),
            'unique_usernames': len(set(usernames)),
            'formats': formats,
            'format_percentages': {
                fmt: (count / len(usernames) * 100) if usernames else 0
                for fmt, count in formats.items()
            }
        }

    def _analyze_email_domains(self, records: List[Any]) -> Dict[str, Any]:
        """Analyze email domains"""
        domains = []

        for record in records:
            if record.email and '@' in record.email:
                domain = record.email.split('@')[1].lower()
                domains.append(domain)

        if not domains:
            return {}

        domain_counts = Counter(domains)

        return {
            'total_domains': len(set(domains)),
            'top_domains': [
                {'domain': domain, 'count': count}
                for domain, count in domain_counts.most_common(10)
            ],
            'corporate_emails': sum(
                1 for d in domains
                if d not in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            )
        }

    def _find_credential_patterns(self, records: List[Any]) -> Dict[str, Any]:
        """Find common credential patterns"""
        patterns = {
            'email_as_username': 0,
            'name_in_email': 0,
            'name_in_password': 0,
            'reused_passwords': 0
        }

        passwords_seen = set()
        password_reuse = 0

        for record in records:
            # Check if email is used as username
            if record.email and record.username:
                if record.email.lower() == record.username.lower():
                    patterns['email_as_username'] += 1

            # Check for name in email
            if record.name and record.email:
                name_parts = record.name.lower().split()
                email_lower = record.email.lower()
                if any(part in email_lower for part in name_parts if len(part) > 2):
                    patterns['name_in_email'] += 1

            # Check for password reuse
            if record.password:
                if record.password in passwords_seen:
                    patterns['reused_passwords'] += 1
                passwords_seen.add(record.password)

        return patterns

    def _generate_recommendations(
        self,
        passwords: List[str],
        records: List[Any]
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if not passwords:
            return recommendations

        # Check for weak passwords
        weak_count = sum(1 for p in passwords if p.lower() in self.weak_passwords)
        if weak_count > 0:
            recommendations.append(
                f"Found {weak_count} commonly used weak passwords - immediate password change required"
            )

        # Check for short passwords
        short_count = sum(1 for p in passwords if len(p) < 8)
        if short_count > 0:
            recommendations.append(
                f"Found {short_count} passwords under 8 characters - recommend 12+ character passwords"
            )

        # Check for password reuse
        unique_ratio = len(set(passwords)) / len(passwords) if passwords else 1
        if unique_ratio < 0.8:
            recommendations.append(
                "High password reuse detected - each account should have unique password"
            )

        # Check for patterns
        pattern_count = sum(
            1 for p in passwords
            if any(pattern.search(p.lower()) for pattern in self.patterns.values())
        )
        if pattern_count > len(passwords) * 0.3:
            recommendations.append(
                "Many passwords contain predictable patterns - avoid sequential and keyboard patterns"
            )

        # Check for personal info in passwords
        personal_count = sum(
            1 for r in records
            if r.password and r.name and r.name.lower() in r.password.lower()
        )
        if personal_count > 0:
            recommendations.append(
                "Personal information found in passwords - avoid using names, birthdays, or other personal data"
            )

        return recommendations

    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0.0

        # Calculate character space
        char_space = 0
        if any(c.islower() for c in password):
            char_space += 26
        if any(c.isupper() for c in password):
            char_space += 26
        if any(c.isdigit() for c in password):
            char_space += 10
        if any(c in string.punctuation for c in password):
            char_space += 32

        # Entropy = log2(char_space^length)
        import math
        entropy = len(password) * math.log2(char_space) if char_space > 0 else 0

        return entropy

    def _calculate_strength(self, password: str) -> str:
        """Calculate password strength"""
        score = 0

        # Length
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1

        # Complexity
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1

        # Penalties
        if password.lower() in self.weak_passwords:
            score -= 3
        if any(pattern.search(password.lower()) for pattern in self.patterns.values()):
            score -= 1

        # Classify
        if score <= 1:
            return 'very_weak'
        elif score == 2:
            return 'weak'
        elif score == 3:
            return 'medium'
        elif score == 4:
            return 'strong'
        else:
            return 'very_strong'

    def _estimate_crack_time(self, password: str) -> str:
        """Estimate time to crack password"""
        entropy = self._calculate_entropy(password)

        # Rough estimates based on entropy
        if entropy < 28:
            return 'instant'
        elif entropy < 36:
            return 'minutes'
        elif entropy < 45:
            return 'hours'
        elif entropy < 60:
            return 'days'
        elif entropy < 80:
            return 'months'
        else:
            return 'years'

    def _calculate_average_security_score(self, passwords: List[str]) -> float:
        """Calculate average security score"""
        if not passwords:
            return 0.0

        scores = []
        for password in passwords:
            entropy = self._calculate_entropy(password)
            # Normalize to 0-100 scale
            score = min(100, (entropy / 100) * 100)
            scores.append(score)

        return sum(scores) / len(scores)

    def _extract_base_words(self, passwords: List[str]) -> List[Dict[str, Any]]:
        """Extract common base words from passwords"""
        base_words = Counter()

        for password in passwords:
            # Remove numbers and special characters
            base = re.sub(r'[^a-zA-Z]', '', password)
            if len(base) >= 4:
                base_words[base.lower()] += 1

        return [
            {'word': word, 'count': count}
            for word, count in base_words.most_common(20)
            if count > 1
        ]

    def _find_numbering_patterns(self, passwords: List[str]) -> List[Dict[str, Any]]:
        """Find numbering patterns in passwords"""
        patterns = defaultdict(list)

        for password in passwords:
            # Extract base and number
            match = re.match(r'(.+?)(\d+)$', password)
            if match:
                base, number = match.groups()
                patterns[base].append(int(number))

        result = []
        for base, numbers in patterns.items():
            if len(numbers) > 1:
                result.append({
                    'base': base,
                    'numbers': sorted(numbers),
                    'count': len(numbers)
                })

        return sorted(result, key=lambda x: x['count'], reverse=True)[:10]


if __name__ == "__main__":
    # Example usage
    from dataclasses import dataclass

    @dataclass
    class MockRecord:
        email: str = None
        username: str = None
        password: str = None
        name: str = None
        database: str = None

    records = [
        MockRecord(email='john.doe@example.com', username='johndoe',
                  password='Password123', name='John Doe'),
        MockRecord(email='john.doe@example.com', username='johndoe',
                  password='Password124', name='John Doe'),
        MockRecord(email='jane@example.com', username='jane_doe',
                  password='qwerty123', name='Jane Doe'),
    ]

    analyzer = CredentialAnalyzer()
    results = analyzer.analyze_credentials(records)

    print("Password Analysis:")
    print(f"Average Entropy: {results['password_analysis']['average_entropy']:.2f}")
    print(f"\nSecurity Distribution:")
    for level, count in results['security_analysis']['strength_distribution'].items():
        print(f"  {level}: {count}")

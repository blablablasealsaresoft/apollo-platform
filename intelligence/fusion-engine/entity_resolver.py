"""
Entity Resolution System
Fuzzy matching, deduplication, and entity merging with conflict resolution
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from difflib import SequenceMatcher
import phonenumbers
from email_validator import validate_email, EmailNotValidError


@dataclass
class ResolvedEntity:
    """Resolved entity with merged attributes"""
    entity_id: str
    primary_identifier: str
    type: str
    attributes: Dict[str, Any]
    aliases: List[str]
    source_id: str
    confidence: float


class EntityResolver:
    """
    Entity Resolution Engine
    Performs fuzzy matching, deduplication, and entity merging
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Entity Resolver

        Args:
            config: Configuration dictionary
        """
        self.fuzzy_threshold = config.get('fuzzy_threshold', 0.85)
        self.email_exact_match = config.get('email_exact_match', True)
        self.phone_normalize = config.get('phone_normalize', True)

        self.entity_cache: Dict[str, ResolvedEntity] = {}

    def resolve_entities(self, intelligence_sources: List[Any],
                        target: str) -> List[Dict[str, Any]]:
        """
        Resolve entities from multiple intelligence sources

        Args:
            intelligence_sources: List of IntelligenceSource objects
            target: Primary target identifier

        Returns:
            List of resolved entity dictionaries
        """
        # Extract potential entities from all sources
        candidates = []
        for source in intelligence_sources:
            entities = self._extract_entities(source.data, source.source_id)
            candidates.extend(entities)

        # Deduplicate and merge entities
        resolved = self._deduplicate_entities(candidates, target)

        return [self._entity_to_dict(e) for e in resolved]

    def _extract_entities(self, data: Dict[str, Any], source_id: str) -> List[ResolvedEntity]:
        """Extract potential entities from raw data"""
        entities = []

        # Email-based entity
        if 'email' in data:
            entity = self._create_entity_from_email(data, source_id)
            if entity:
                entities.append(entity)

        # Phone-based entity
        if 'phone' in data:
            entity = self._create_entity_from_phone(data, source_id)
            if entity:
                entities.append(entity)

        # Name-based entity
        if 'name' in data:
            entity = self._create_entity_from_name(data, source_id)
            if entity:
                entities.append(entity)

        # Wallet-based entity
        if 'wallet' in data or 'address' in data:
            entity = self._create_entity_from_wallet(data, source_id)
            if entity:
                entities.append(entity)

        return entities

    def _create_entity_from_email(self, data: Dict[str, Any], source_id: str) -> Optional[ResolvedEntity]:
        """Create entity from email identifier"""
        email = data.get('email', '').strip().lower()

        if not email:
            return None

        # Validate email
        try:
            valid = validate_email(email, check_deliverability=False)
            email = valid.email
        except (EmailNotValidError, Exception):
            return None

        entity_id = hashlib.sha256(f"email:{email}".encode()).hexdigest()[:16]

        attributes = {
            'email': email,
            'domain': email.split('@')[1] if '@' in email else None
        }

        # Extract additional attributes
        for key in ['name', 'username', 'location', 'phone', 'organization']:
            if key in data:
                attributes[key] = data[key]

        # Extract aliases
        aliases = []
        if 'aliases' in data:
            aliases = data['aliases'] if isinstance(data['aliases'], list) else [data['aliases']]
        if 'username' in data:
            aliases.append(data['username'])

        return ResolvedEntity(
            entity_id=entity_id,
            primary_identifier=email,
            type='email',
            attributes=attributes,
            aliases=aliases,
            source_id=source_id,
            confidence=0.9
        )

    def _create_entity_from_phone(self, data: Dict[str, Any], source_id: str) -> Optional[ResolvedEntity]:
        """Create entity from phone identifier"""
        phone = data.get('phone', '').strip()

        if not phone:
            return None

        # Normalize phone number
        if self.phone_normalize:
            phone = self._normalize_phone(phone)

        if not phone:
            return None

        entity_id = hashlib.sha256(f"phone:{phone}".encode()).hexdigest()[:16]

        attributes = {
            'phone': phone
        }

        for key in ['name', 'email', 'location', 'carrier']:
            if key in data:
                attributes[key] = data[key]

        return ResolvedEntity(
            entity_id=entity_id,
            primary_identifier=phone,
            type='phone',
            attributes=attributes,
            aliases=[],
            source_id=source_id,
            confidence=0.85
        )

    def _create_entity_from_name(self, data: Dict[str, Any], source_id: str) -> Optional[ResolvedEntity]:
        """Create entity from name identifier"""
        name = data.get('name', '').strip()

        if not name or len(name) < 2:
            return None

        normalized_name = self._normalize_name(name)
        entity_id = hashlib.sha256(f"name:{normalized_name}".encode()).hexdigest()[:16]

        attributes = {
            'name': name,
            'normalized_name': normalized_name
        }

        for key in ['email', 'phone', 'location', 'age', 'occupation']:
            if key in data:
                attributes[key] = data[key]

        aliases = data.get('aliases', [])
        if isinstance(aliases, str):
            aliases = [aliases]

        return ResolvedEntity(
            entity_id=entity_id,
            primary_identifier=name,
            type='person',
            attributes=attributes,
            aliases=aliases,
            source_id=source_id,
            confidence=0.75
        )

    def _create_entity_from_wallet(self, data: Dict[str, Any], source_id: str) -> Optional[ResolvedEntity]:
        """Create entity from cryptocurrency wallet"""
        wallet = data.get('wallet') or data.get('address', '').strip()

        if not wallet:
            return None

        entity_id = hashlib.sha256(f"wallet:{wallet}".encode()).hexdigest()[:16]

        attributes = {
            'wallet': wallet,
            'blockchain': self._detect_blockchain(wallet)
        }

        for key in ['owner_email', 'owner_name', 'balance', 'transactions']:
            if key in data:
                attributes[key] = data[key]

        return ResolvedEntity(
            entity_id=entity_id,
            primary_identifier=wallet,
            type='wallet',
            attributes=attributes,
            aliases=[],
            source_id=source_id,
            confidence=0.95
        )

    def _deduplicate_entities(self, entities: List[ResolvedEntity],
                             target: str) -> List[ResolvedEntity]:
        """
        Deduplicate entities using fuzzy matching and merge duplicates

        Args:
            entities: List of candidate entities
            target: Primary target identifier

        Returns:
            Deduplicated list of entities
        """
        if not entities:
            return []

        # Group entities by type
        by_type: Dict[str, List[ResolvedEntity]] = {}
        for entity in entities:
            if entity.type not in by_type:
                by_type[entity.type] = []
            by_type[entity.type].append(entity)

        # Deduplicate within each type
        deduplicated = []
        for entity_type, type_entities in by_type.items():
            if entity_type == 'email':
                deduped = self._deduplicate_emails(type_entities)
            elif entity_type == 'phone':
                deduped = self._deduplicate_phones(type_entities)
            elif entity_type == 'person':
                deduped = self._deduplicate_persons(type_entities)
            elif entity_type == 'wallet':
                deduped = self._deduplicate_wallets(type_entities)
            else:
                deduped = type_entities

            deduplicated.extend(deduped)

        return deduplicated

    def _deduplicate_emails(self, entities: List[ResolvedEntity]) -> List[ResolvedEntity]:
        """Deduplicate email entities (exact match)"""
        seen = {}

        for entity in entities:
            email = entity.attributes.get('email', '').lower()

            if email not in seen:
                seen[email] = entity
            else:
                # Merge attributes
                seen[email] = self._merge_entities(seen[email], entity)

        return list(seen.values())

    def _deduplicate_phones(self, entities: List[ResolvedEntity]) -> List[ResolvedEntity]:
        """Deduplicate phone entities (normalized match)"""
        seen = {}

        for entity in entities:
            phone = self._normalize_phone(entity.attributes.get('phone', ''))

            if phone not in seen:
                seen[phone] = entity
            else:
                seen[phone] = self._merge_entities(seen[phone], entity)

        return list(seen.values())

    def _deduplicate_persons(self, entities: List[ResolvedEntity]) -> List[ResolvedEntity]:
        """Deduplicate person entities (fuzzy name matching)"""
        deduplicated = []

        for entity in entities:
            # Check if similar entity already exists
            matched = False
            for existing in deduplicated:
                if self._names_match(entity.attributes.get('name', ''),
                                   existing.attributes.get('name', '')):
                    # Merge with existing
                    merged_idx = deduplicated.index(existing)
                    deduplicated[merged_idx] = self._merge_entities(existing, entity)
                    matched = True
                    break

            if not matched:
                deduplicated.append(entity)

        return deduplicated

    def _deduplicate_wallets(self, entities: List[ResolvedEntity]) -> List[ResolvedEntity]:
        """Deduplicate wallet entities (exact match)"""
        seen = {}

        for entity in entities:
            wallet = entity.attributes.get('wallet', '').lower()

            if wallet not in seen:
                seen[wallet] = entity
            else:
                seen[wallet] = self._merge_entities(seen[wallet], entity)

        return list(seen.values())

    def _merge_entities(self, entity1: ResolvedEntity, entity2: ResolvedEntity) -> ResolvedEntity:
        """
        Merge two entities with conflict resolution

        Priority: Higher confidence wins, newer data wins on tie
        """
        # Determine primary entity (higher confidence)
        if entity1.confidence >= entity2.confidence:
            primary, secondary = entity1, entity2
        else:
            primary, secondary = entity2, entity1

        # Merge attributes
        merged_attrs = dict(primary.attributes)
        for key, value in secondary.attributes.items():
            if key not in merged_attrs:
                merged_attrs[key] = value
            elif isinstance(value, list):
                # Merge lists
                existing = merged_attrs[key]
                if isinstance(existing, list):
                    merged_attrs[key] = list(set(existing + value))
                else:
                    merged_attrs[key] = [existing, value]
            elif key == 'name' and self._names_match(merged_attrs[key], value):
                # Keep more complete name
                if len(value) > len(merged_attrs[key]):
                    merged_attrs[key] = value

        # Merge aliases
        merged_aliases = list(set(primary.aliases + secondary.aliases))

        # Average confidence weighted by number of sources
        merged_confidence = (primary.confidence + secondary.confidence) / 2

        return ResolvedEntity(
            entity_id=primary.entity_id,
            primary_identifier=primary.primary_identifier,
            type=primary.type,
            attributes=merged_attrs,
            aliases=merged_aliases,
            source_id=f"{primary.source_id}+{secondary.source_id}",
            confidence=min(merged_confidence * 1.1, 1.0)  # Bonus for corroboration
        )

    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number to E.164 format"""
        try:
            parsed = phonenumbers.parse(phone, None)
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            pass

        # Fallback: strip non-digits
        digits = re.sub(r'\D', '', phone)
        return f"+{digits}" if digits else ""

    def _normalize_name(self, name: str) -> str:
        """Normalize name for comparison"""
        # Convert to lowercase, remove extra spaces, punctuation
        normalized = name.lower().strip()
        normalized = re.sub(r'[^\w\s]', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized

    def _names_match(self, name1: str, name2: str) -> bool:
        """Check if two names match using fuzzy matching"""
        if not name1 or not name2:
            return False

        norm1 = self._normalize_name(name1)
        norm2 = self._normalize_name(name2)

        # Exact match after normalization
        if norm1 == norm2:
            return True

        # Fuzzy match using SequenceMatcher
        similarity = SequenceMatcher(None, norm1, norm2).ratio()
        return similarity >= self.fuzzy_threshold

    def _detect_blockchain(self, wallet: str) -> str:
        """Detect blockchain type from wallet address"""
        if wallet.startswith('0x') and len(wallet) == 42:
            return 'Ethereum'
        elif wallet.startswith('bc1') or wallet.startswith('1') or wallet.startswith('3'):
            return 'Bitcoin'
        elif wallet.startswith('X'):
            return 'Monero'
        elif wallet.startswith('r'):
            return 'Ripple'
        else:
            return 'Unknown'

    def _entity_to_dict(self, entity: ResolvedEntity) -> Dict[str, Any]:
        """Convert ResolvedEntity to dictionary"""
        return {
            'entity_id': entity.entity_id,
            'primary_identifier': entity.primary_identifier,
            'type': entity.type,
            'attributes': entity.attributes,
            'aliases': entity.aliases,
            'source_id': entity.source_id,
            'confidence': entity.confidence
        }

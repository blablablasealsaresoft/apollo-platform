"""
Address Intelligence Module
Physical address validation, geocoding, and intelligence gathering
"""

import logging
import requests
from typing import Dict, Optional, List
import json
from datetime import datetime
from geopy.geocoders import Nominatim, GoogleV3, Bing
from geopy.exc import GeocoderTimedOut, GeocoderServiceError


class AddressIntelligence:
    """Address Intelligence and Analysis"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize Address Intelligence module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys
        self.google_key = self.config.get('google_maps_key')
        self.bing_key = self.config.get('bing_maps_key')
        self.here_key = self.config.get('here_api_key')

        # Initialize geocoders
        self.nominatim = Nominatim(user_agent="GEOINT-AddressAnalyzer/1.0")
        self.google_geocoder = GoogleV3(api_key=self.google_key) if self.google_key else None
        self.bing_geocoder = Bing(api_key=self.bing_key) if self.bing_key else None

        # Cache
        self.cache = {}

    def analyze(self, address: str, country: Optional[str] = None) -> Dict:
        """
        Comprehensive address analysis

        Args:
            address: Address string to analyze
            country: Optional country code for better accuracy

        Returns:
            Dictionary with address intelligence
        """
        # Check cache
        cache_key = f"{address}_{country}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        result = {
            'input_address': address,
            'timestamp': datetime.now().isoformat(),
            'is_valid': False,
            'formatted_address': None,
            'coordinates': {},
            'components': {},
            'nearby_pois': [],
            'property_data': {},
            'demographics': {},
            'confidence': 0.0
        }

        try:
            # Validate and geocode
            geocode_result = self._geocode(address, country)
            if geocode_result:
                result['is_valid'] = True
                result['formatted_address'] = geocode_result.get('formatted_address')
                result['coordinates'] = geocode_result.get('coordinates', {})
                result['components'] = geocode_result.get('components', {})
                result['confidence'] = geocode_result.get('confidence', 0.7)

                # Find nearby points of interest
                if result['coordinates']:
                    result['nearby_pois'] = self._find_nearby_pois(
                        result['coordinates']['latitude'],
                        result['coordinates']['longitude']
                    )

                # Get property data (if available)
                result['property_data'] = self._get_property_data(address)

                # Get demographics
                if result['components'].get('postal_code'):
                    result['demographics'] = self._get_demographics(
                        result['components']['postal_code']
                    )

        except Exception as e:
            self.logger.error(f"Address analysis error: {e}")
            result['error'] = str(e)

        # Cache result
        self.cache[cache_key] = result

        return result

    def _geocode(self, address: str, country: Optional[str] = None) -> Optional[Dict]:
        """
        Geocode address to coordinates using multiple providers

        Args:
            address: Address to geocode
            country: Optional country code

        Returns:
            Geocoding result dictionary
        """
        # Try multiple geocoders for best results
        geocoders = []

        if self.google_geocoder:
            geocoders.append(('google', self.google_geocoder))
        if self.bing_geocoder:
            geocoders.append(('bing', self.bing_geocoder))
        geocoders.append(('nominatim', self.nominatim))

        for provider_name, geocoder in geocoders:
            try:
                query = f"{address}, {country}" if country else address
                location = geocoder.geocode(query, timeout=10)

                if location:
                    result = {
                        'provider': provider_name,
                        'formatted_address': location.address,
                        'coordinates': {
                            'latitude': location.latitude,
                            'longitude': location.longitude
                        },
                        'confidence': 0.8
                    }

                    # Extract address components
                    if hasattr(location, 'raw'):
                        result['components'] = self._parse_components(
                            location.raw,
                            provider_name
                        )

                    return result

            except (GeocoderTimedOut, GeocoderServiceError) as e:
                self.logger.warning(f"{provider_name} geocoding failed: {e}")
                continue
            except Exception as e:
                self.logger.error(f"{provider_name} geocoding error: {e}")
                continue

        return None

    def _parse_components(self, raw_data: Dict, provider: str) -> Dict:
        """Parse address components from geocoder response"""
        components = {}

        try:
            if provider == 'google':
                for component in raw_data.get('address_components', []):
                    types = component.get('types', [])
                    value = component.get('long_name')

                    if 'street_number' in types:
                        components['street_number'] = value
                    elif 'route' in types:
                        components['street'] = value
                    elif 'locality' in types:
                        components['city'] = value
                    elif 'administrative_area_level_1' in types:
                        components['state'] = value
                    elif 'country' in types:
                        components['country'] = value
                        components['country_code'] = component.get('short_name')
                    elif 'postal_code' in types:
                        components['postal_code'] = value

            elif provider == 'nominatim':
                address = raw_data.get('address', {})
                components = {
                    'street_number': address.get('house_number'),
                    'street': address.get('road'),
                    'city': address.get('city') or address.get('town') or address.get('village'),
                    'state': address.get('state'),
                    'country': address.get('country'),
                    'country_code': address.get('country_code'),
                    'postal_code': address.get('postcode')
                }

            elif provider == 'bing':
                address = raw_data.get('address', {})
                components = {
                    'street': address.get('addressLine'),
                    'city': address.get('locality'),
                    'state': address.get('adminDistrict'),
                    'country': address.get('countryRegion'),
                    'postal_code': address.get('postalCode')
                }

        except Exception as e:
            self.logger.error(f"Component parsing error: {e}")

        return components

    def reverse_geocode(self, latitude: float, longitude: float) -> Dict:
        """
        Reverse geocode coordinates to address

        Args:
            latitude: Latitude
            longitude: Longitude

        Returns:
            Address information
        """
        result = {
            'latitude': latitude,
            'longitude': longitude,
            'addresses': []
        }

        # Try multiple geocoders
        geocoders = [
            ('nominatim', self.nominatim),
            ('google', self.google_geocoder),
            ('bing', self.bing_geocoder)
        ]

        for provider_name, geocoder in geocoders:
            if not geocoder:
                continue

            try:
                location = geocoder.reverse(f"{latitude}, {longitude}", timeout=10)

                if location:
                    address_data = {
                        'provider': provider_name,
                        'formatted_address': location.address,
                        'components': {}
                    }

                    if hasattr(location, 'raw'):
                        address_data['components'] = self._parse_components(
                            location.raw,
                            provider_name
                        )

                    result['addresses'].append(address_data)

            except Exception as e:
                self.logger.error(f"{provider_name} reverse geocoding error: {e}")

        return result

    def _find_nearby_pois(self, latitude: float, longitude: float, radius: int = 1000) -> List[Dict]:
        """
        Find nearby points of interest

        Args:
            latitude: Latitude
            longitude: Longitude
            radius: Search radius in meters

        Returns:
            List of nearby POIs
        """
        pois = []

        try:
            # Use Overpass API (OpenStreetMap) for POI search
            overpass_url = "http://overpass-api.de/api/interpreter"

            # Query for various amenities
            query = f"""
            [out:json];
            (
              node["amenity"](around:{radius},{latitude},{longitude});
              node["shop"](around:{radius},{latitude},{longitude});
              node["tourism"](around:{radius},{latitude},{longitude});
            );
            out body;
            """

            response = requests.post(overpass_url, data={'data': query}, timeout=30)
            response.raise_for_status()
            data = response.json()

            for element in data.get('elements', []):
                tags = element.get('tags', {})
                poi = {
                    'type': tags.get('amenity') or tags.get('shop') or tags.get('tourism'),
                    'name': tags.get('name'),
                    'latitude': element.get('lat'),
                    'longitude': element.get('lon'),
                    'address': tags.get('addr:street'),
                    'phone': tags.get('phone'),
                    'website': tags.get('website')
                }
                if poi['type']:
                    pois.append(poi)

        except Exception as e:
            self.logger.error(f"POI search error: {e}")

        return pois[:20]  # Limit to 20 results

    def _get_property_data(self, address: str) -> Dict:
        """
        Get property records and data

        This would integrate with property databases like:
        - Public records
        - Property assessment data
        - Real estate APIs
        """
        property_data = {
            'owner': None,
            'value': None,
            'tax_assessment': None,
            'year_built': None,
            'square_feet': None,
            'lot_size': None,
            'bedrooms': None,
            'bathrooms': None,
            'property_type': None
        }

        try:
            # Placeholder for property data API integration
            # Would require services like:
            # - Zillow API
            # - Realtor.com API
            # - Public records databases

            if self.config.get('zillow_key'):
                # Example Zillow integration
                pass

        except Exception as e:
            self.logger.error(f"Property data lookup error: {e}")

        return property_data

    def _get_demographics(self, postal_code: str) -> Dict:
        """
        Get demographic data for area

        Args:
            postal_code: Postal/ZIP code

        Returns:
            Demographic information
        """
        demographics = {
            'population': None,
            'median_age': None,
            'median_income': None,
            'education_level': None,
            'employment_rate': None
        }

        try:
            # This would integrate with census/demographic APIs
            # - US Census API
            # - World Population Review
            # - Demographics APIs

            if self.config.get('census_key'):
                # Example Census API integration
                pass

        except Exception as e:
            self.logger.error(f"Demographics lookup error: {e}")

        return demographics

    def validate_address(self, address: str, country: Optional[str] = None) -> bool:
        """
        Validate if address exists

        Args:
            address: Address to validate
            country: Optional country code

        Returns:
            True if valid, False otherwise
        """
        try:
            result = self._geocode(address, country)
            return result is not None
        except Exception:
            return False

    def standardize_address(self, address: str) -> Optional[str]:
        """
        Standardize address format

        Args:
            address: Address to standardize

        Returns:
            Standardized address string
        """
        try:
            geocode_result = self._geocode(address)
            if geocode_result:
                return geocode_result.get('formatted_address')
        except Exception as e:
            self.logger.error(f"Address standardization error: {e}")

        return None

    def calculate_distance(self, address1: str, address2: str) -> Optional[float]:
        """
        Calculate distance between two addresses

        Args:
            address1: First address
            address2: Second address

        Returns:
            Distance in kilometers
        """
        try:
            # Geocode both addresses
            loc1 = self._geocode(address1)
            loc2 = self._geocode(address2)

            if loc1 and loc2:
                coords1 = loc1['coordinates']
                coords2 = loc2['coordinates']

                # Haversine formula
                from math import radians, sin, cos, sqrt, atan2

                R = 6371  # Earth radius in km

                lat1 = radians(coords1['latitude'])
                lon1 = radians(coords1['longitude'])
                lat2 = radians(coords2['latitude'])
                lon2 = radians(coords2['longitude'])

                dlat = lat2 - lat1
                dlon = lon2 - lon1

                a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
                c = 2 * atan2(sqrt(a), sqrt(1-a))

                return R * c

        except Exception as e:
            self.logger.error(f"Distance calculation error: {e}")

        return None

    def batch_geocode(self, addresses: List[str]) -> List[Dict]:
        """Batch geocode multiple addresses"""
        results = []
        for address in addresses:
            try:
                result = self.analyze(address)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch geocoding failed for {address}: {e}")
                results.append({'input_address': address, 'error': str(e)})
        return results


if __name__ == "__main__":
    # Example usage
    addr_intel = AddressIntelligence({
        'google_maps_key': 'your_key_here'
    })

    # Analyze address
    result = addr_intel.analyze("1600 Amphitheatre Parkway, Mountain View, CA")
    print(json.dumps(result, indent=2))

    # Reverse geocode
    reverse_result = addr_intel.reverse_geocode(37.4224764, -122.0842499)
    print(json.dumps(reverse_result, indent=2))

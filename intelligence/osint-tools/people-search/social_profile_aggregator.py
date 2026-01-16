"""
Social Profile Aggregator - Link and Aggregate All Social Media Profiles
Username correlation, activity timeline, and network visualization
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json
import hashlib
from urllib.parse import urlparse, quote_plus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SocialProfile:
    """Individual social media profile"""
    platform: str
    username: str
    url: str
    profile_id: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    post_count: Optional[int] = None
    verified: bool = False
    created_date: Optional[str] = None
    last_active: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0


@dataclass
class SocialNetwork:
    """Complete social network profile"""
    primary_name: str
    usernames: Set[str] = field(default_factory=set)
    profiles: List[SocialProfile] = field(default_factory=list)

    # Cross-platform data
    email_addresses: Set[str] = field(default_factory=set)
    phone_numbers: Set[str] = field(default_factory=set)
    websites: Set[str] = field(default_factory=set)
    locations: Set[str] = field(default_factory=set)

    # Activity timeline
    activity_timeline: List[Dict[str, Any]] = field(default_factory=list)

    # Network connections
    connections: Dict[str, List[str]] = field(default_factory=dict)

    # Metadata
    total_followers: int = 0
    total_following: int = 0
    total_posts: int = 0
    platforms_found: int = 0
    search_date: str = field(default_factory=lambda: datetime.now().isoformat())


class SocialProfileAggregator:
    """
    Social media profile aggregation and correlation

    Features:
    - Multi-platform username search
    - Profile linking and correlation
    - Activity timeline generation
    - Network visualization data
    - Cross-platform analytics
    """

    # Platform search URLs
    PLATFORMS = {
        'twitter': 'https://twitter.com/{}',
        'facebook': 'https://www.facebook.com/{}',
        'instagram': 'https://www.instagram.com/{}',
        'linkedin': 'https://www.linkedin.com/in/{}',
        'github': 'https://github.com/{}',
        'reddit': 'https://www.reddit.com/user/{}',
        'tiktok': 'https://www.tiktok.com/@{}',
        'youtube': 'https://www.youtube.com/@{}',
        'pinterest': 'https://www.pinterest.com/{}',
        'snapchat': 'https://www.snapchat.com/add/{}',
        'telegram': 'https://t.me/{}',
        'discord': 'https://discord.com/users/{}',
        'twitch': 'https://www.twitch.tv/{}',
        'medium': 'https://medium.com/@{}',
        'tumblr': 'https://{}.tumblr.com',
        'vimeo': 'https://vimeo.com/{}',
        'flickr': 'https://www.flickr.com/photos/{}',
        'soundcloud': 'https://soundcloud.com/{}',
        'spotify': 'https://open.spotify.com/user/{}',
        'steam': 'https://steamcommunity.com/id/{}',
        'xbox': 'https://xboxgamertag.com/search/{}',
        'playstation': 'https://my.playstation.com/profile/{}',
        'patreon': 'https://www.patreon.com/{}',
        'onlyfans': 'https://onlyfans.com/{}',
        'cashapp': 'https://cash.app/${}',
        'venmo': 'https://venmo.com/{}',
        'linktree': 'https://linktr.ee/{}',
        'aboutme': 'https://about.me/{}',
        'wordpress': 'https://{}.wordpress.com',
        'blogger': 'https://{}.blogspot.com',
        'deviantart': 'https://www.deviantart.com/{}',
        'behance': 'https://www.behance.net/{}',
        'dribbble': 'https://dribbble.com/{}',
        'kaggle': 'https://www.kaggle.com/{}',
        'stackoverflow': 'https://stackoverflow.com/users/{}',
        'hackerone': 'https://hackerone.com/{}',
        'keybase': 'https://keybase.io/{}',
        'gitlab': 'https://gitlab.com/{}',
        'bitbucket': 'https://bitbucket.org/{}',
        'producthunt': 'https://www.producthunt.com/@{}',
        'angellist': 'https://angel.co/u/{}',
        'clubhouse': 'https://www.clubhouse.com/@{}',
        'gab': 'https://gab.com/{}',
        'parler': 'https://parler.com/profile/{}',
        'minds': 'https://www.minds.com/{}',
        'vk': 'https://vk.com/{}',
        'ok': 'https://ok.ru/{}',
        'weibo': 'https://weibo.com/{}',
        'qq': 'https://user.qzone.qq.com/{}',
        'wechat': 'https://weixin.qq.com/{}',
        'line': 'https://line.me/ti/p/{}',
        'whatsapp': 'https://wa.me/{}',
    }

    def __init__(self):
        """Initialize social profile aggregator"""
        self.session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, SocialProfile] = {}

    async def __aenter__(self):
        """Async context manager entry"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def search_username(
        self,
        username: str,
        platforms: Optional[List[str]] = None
    ) -> SocialNetwork:
        """
        Search for username across social media platforms

        Args:
            username: Username to search
            platforms: Specific platforms to search (None = all)

        Returns:
            SocialNetwork with all found profiles
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        logger.info(f"Searching for username: {username}")

        network = SocialNetwork(primary_name=username)
        network.usernames.add(username)

        # Determine platforms to search
        search_platforms = platforms if platforms else list(self.PLATFORMS.keys())

        # Search all platforms in parallel
        tasks = [
            self._check_platform(username, platform)
            for platform in search_platforms
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, SocialProfile) and result.confidence_score > 0.5:
                network.profiles.append(result)
                network.platforms_found += 1

                # Aggregate data
                if result.email:
                    network.email_addresses.add(result.email)
                if result.phone:
                    network.phone_numbers.add(result.phone)
                if result.website:
                    network.websites.add(result.website)
                if result.location:
                    network.locations.add(result.location)

                # Update totals
                if result.followers:
                    network.total_followers += result.followers
                if result.following:
                    network.total_following += result.following
                if result.post_count:
                    network.total_posts += result.post_count

        logger.info(f"Found {network.platforms_found} profiles for username: {username}")
        return network

    async def search_name(
        self,
        name: str,
        additional_info: Optional[Dict[str, str]] = None
    ) -> SocialNetwork:
        """
        Search for person by real name

        Args:
            name: Person's real name
            additional_info: Location, company, etc.

        Returns:
            SocialNetwork with discovered profiles
        """
        logger.info(f"Searching for name: {name}")

        network = SocialNetwork(primary_name=name)

        # Generate potential usernames
        potential_usernames = self._generate_usernames(name)

        # Search each potential username
        tasks = [
            self.search_username(username)
            for username in potential_usernames[:10]  # Limit to top 10
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results
        for result in results:
            if isinstance(result, SocialNetwork):
                network.profiles.extend(result.profiles)
                network.usernames.update(result.usernames)
                network.email_addresses.update(result.email_addresses)
                network.platforms_found = len(network.profiles)

        return network

    async def _check_platform(
        self,
        username: str,
        platform: str
    ) -> Optional[SocialProfile]:
        """Check if username exists on specific platform"""
        try:
            # Get platform URL template
            url_template = self.PLATFORMS.get(platform)
            if not url_template:
                return None

            # Format URL
            url = url_template.format(username)

            # Check cache
            cache_key = hashlib.md5(f"{platform}:{username}".encode()).hexdigest()
            if cache_key in self._cache:
                return self._cache[cache_key]

            # Make request
            async with self.session.get(url, timeout=10, allow_redirects=True) as response:
                if response.status == 200:
                    # Profile exists
                    html = await response.text()
                    profile = await self._parse_profile(platform, username, url, html)

                    # Cache result
                    self._cache[cache_key] = profile
                    return profile
                elif response.status == 404:
                    # Profile doesn't exist
                    return None
                else:
                    # Uncertain
                    return None

        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking {platform} for {username}")
            return None
        except Exception as e:
            logger.debug(f"Error checking {platform} for {username}: {e}")
            return None

    async def _parse_profile(
        self,
        platform: str,
        username: str,
        url: str,
        html: str
    ) -> SocialProfile:
        """Parse profile page to extract information"""
        from bs4 import BeautifulSoup

        profile = SocialProfile(
            platform=platform,
            username=username,
            url=url,
            confidence_score=0.7  # Base confidence
        )

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Platform-specific parsing
            if platform == 'twitter':
                profile = self._parse_twitter(soup, profile)
            elif platform == 'instagram':
                profile = self._parse_instagram(soup, profile)
            elif platform == 'linkedin':
                profile = self._parse_linkedin(soup, profile)
            elif platform == 'github':
                profile = self._parse_github(soup, profile)
            elif platform == 'facebook':
                profile = self._parse_facebook(soup, profile)
            else:
                # Generic parsing
                profile = self._parse_generic(soup, profile)

        except Exception as e:
            logger.debug(f"Error parsing {platform} profile: {e}")

        return profile

    def _parse_twitter(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Parse Twitter profile"""
        try:
            # Look for JSON-LD data
            json_ld = soup.find('script', {'type': 'application/ld+json'})
            if json_ld:
                data = json.loads(json_ld.string)
                profile.display_name = data.get('name')
                profile.bio = data.get('description')
                profile.avatar_url = data.get('image')

            # Confidence boost if verified
            if soup.find('svg', {'aria-label': 'Verified account'}):
                profile.verified = True
                profile.confidence_score = 0.95

        except Exception as e:
            logger.debug(f"Twitter parsing error: {e}")

        return profile

    def _parse_instagram(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Parse Instagram profile"""
        try:
            # Instagram often has JSON data in meta tags
            meta_description = soup.find('meta', {'property': 'og:description'})
            if meta_description:
                profile.bio = meta_description.get('content')

        except Exception as e:
            logger.debug(f"Instagram parsing error: {e}")

        return profile

    def _parse_linkedin(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Parse LinkedIn profile"""
        try:
            # LinkedIn meta tags
            title = soup.find('meta', {'property': 'og:title'})
            if title:
                profile.display_name = title.get('content')

            description = soup.find('meta', {'property': 'og:description'})
            if description:
                profile.bio = description.get('content')

            profile.confidence_score = 0.85  # LinkedIn profiles are usually reliable

        except Exception as e:
            logger.debug(f"LinkedIn parsing error: {e}")

        return profile

    def _parse_github(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Parse GitHub profile"""
        try:
            # GitHub has structured data
            name_elem = soup.find('span', {'itemprop': 'name'})
            if name_elem:
                profile.display_name = name_elem.text.strip()

            bio_elem = soup.find('div', {'data-bio-text': True})
            if bio_elem:
                profile.bio = bio_elem.text.strip()

            location_elem = soup.find('span', {'itemprop': 'homeLocation'})
            if location_elem:
                profile.location = location_elem.text.strip()

            website_elem = soup.find('a', {'itemprop': 'url'})
            if website_elem:
                profile.website = website_elem.get('href')

            profile.confidence_score = 0.9  # GitHub profiles are highly reliable

        except Exception as e:
            logger.debug(f"GitHub parsing error: {e}")

        return profile

    def _parse_facebook(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Parse Facebook profile"""
        try:
            # Facebook uses meta tags
            title = soup.find('meta', {'property': 'og:title'})
            if title:
                profile.display_name = title.get('content')

        except Exception as e:
            logger.debug(f"Facebook parsing error: {e}")

        return profile

    def _parse_generic(self, soup: BeautifulSoup, profile: SocialProfile) -> SocialProfile:
        """Generic profile parsing"""
        try:
            # Look for common meta tags
            og_title = soup.find('meta', {'property': 'og:title'})
            if og_title:
                profile.display_name = og_title.get('content')

            og_description = soup.find('meta', {'property': 'og:description'})
            if og_description:
                profile.bio = og_description.get('content')

            og_image = soup.find('meta', {'property': 'og:image'})
            if og_image:
                profile.avatar_url = og_image.get('content')

        except Exception as e:
            logger.debug(f"Generic parsing error: {e}")

        return profile

    def _generate_usernames(self, name: str) -> List[str]:
        """Generate potential usernames from real name"""
        usernames = []

        # Clean name
        name = name.lower().strip()
        parts = name.split()

        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]

            # Common patterns
            usernames.extend([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                last,
                first,
                f"{last}{first}",
                f"{first}{last}123",
                f"{first}{last}1",
            ])

        return list(set(usernames))

    async def correlate_profiles(
        self,
        profiles: List[SocialProfile]
    ) -> Dict[str, float]:
        """
        Correlate profiles to determine if they belong to same person

        Args:
            profiles: List of social profiles to correlate

        Returns:
            Correlation scores between profiles
        """
        correlations = {}

        for i, profile1 in enumerate(profiles):
            for profile2 in profiles[i+1:]:
                score = self._calculate_correlation(profile1, profile2)
                key = f"{profile1.platform}:{profile2.platform}"
                correlations[key] = score

        return correlations

    def _calculate_correlation(
        self,
        profile1: SocialProfile,
        profile2: SocialProfile
    ) -> float:
        """Calculate correlation score between two profiles"""
        score = 0.0
        factors = 0

        # Same display name
        if profile1.display_name and profile2.display_name:
            if profile1.display_name.lower() == profile2.display_name.lower():
                score += 30
            factors += 1

        # Same bio keywords
        if profile1.bio and profile2.bio:
            bio1_words = set(profile1.bio.lower().split())
            bio2_words = set(profile2.bio.lower().split())
            overlap = len(bio1_words & bio2_words) / max(len(bio1_words), len(bio2_words))
            score += overlap * 20
            factors += 1

        # Same location
        if profile1.location and profile2.location:
            if profile1.location.lower() == profile2.location.lower():
                score += 20
            factors += 1

        # Same website
        if profile1.website and profile2.website:
            if profile1.website == profile2.website:
                score += 25
            factors += 1

        # Same email
        if profile1.email and profile2.email:
            if profile1.email == profile2.email:
                score += 40
            factors += 1

        # Normalize
        if factors > 0:
            return min(score / factors, 1.0)
        else:
            return 0.0

    def generate_network_graph(self, network: SocialNetwork) -> Dict[str, Any]:
        """
        Generate network visualization data

        Args:
            network: SocialNetwork to visualize

        Returns:
            Graph data structure for visualization
        """
        nodes = []
        edges = []

        # Central node (person)
        nodes.append({
            'id': 'person',
            'label': network.primary_name,
            'type': 'person',
            'size': 50
        })

        # Platform nodes
        for profile in network.profiles:
            nodes.append({
                'id': profile.platform,
                'label': f"{profile.platform}\n@{profile.username}",
                'type': 'platform',
                'size': 30,
                'url': profile.url,
                'followers': profile.followers,
                'verified': profile.verified
            })

            # Edge from person to platform
            edges.append({
                'source': 'person',
                'target': profile.platform,
                'confidence': profile.confidence_score
            })

        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'total_profiles': len(network.profiles),
                'total_followers': network.total_followers,
                'total_following': network.total_following,
                'platforms': network.platforms_found
            }
        }

    def export_network(self, network: SocialNetwork, format: str = 'json') -> str:
        """Export social network data"""
        if format == 'json':
            return json.dumps({
                'primary_name': network.primary_name,
                'usernames': list(network.usernames),
                'profiles': [{
                    'platform': p.platform,
                    'username': p.username,
                    'url': p.url,
                    'display_name': p.display_name,
                    'bio': p.bio,
                    'followers': p.followers,
                    'following': p.following,
                    'verified': p.verified,
                    'confidence': p.confidence_score
                } for p in network.profiles],
                'email_addresses': list(network.email_addresses),
                'phone_numbers': list(network.phone_numbers),
                'websites': list(network.websites),
                'locations': list(network.locations),
                'stats': {
                    'platforms_found': network.platforms_found,
                    'total_followers': network.total_followers,
                    'total_following': network.total_following,
                    'total_posts': network.total_posts
                },
                'search_date': network.search_date
            }, indent=2)

        elif format == 'text':
            return f"""
SOCIAL NETWORK PROFILE
{'='*80}

Name: {network.primary_name}
Known Usernames: {', '.join(network.usernames)}
Platforms Found: {network.platforms_found}
Search Date: {network.search_date}

STATISTICS
{'='*80}

Total Followers: {network.total_followers:,}
Total Following: {network.total_following:,}
Total Posts: {network.total_posts:,}

PROFILES
{'='*80}

{chr(10).join(f"[{p.platform.upper()}] @{p.username}" + (f" - {p.display_name}" if p.display_name else "") + (f" (Verified)" if p.verified else "") + f"\\n  URL: {p.url}\\n  Followers: {p.followers:,}" if p.followers else "" + f"\\n  Confidence: {p.confidence_score:.2f}" for p in network.profiles)}

CONTACT INFORMATION
{'='*80}

Email Addresses:
{chr(10).join(f"  - {email}" for email in network.email_addresses) if network.email_addresses else '  None found'}

Phone Numbers:
{chr(10).join(f"  - {phone}" for phone in network.phone_numbers) if network.phone_numbers else '  None found'}

Websites:
{chr(10).join(f"  - {website}" for website in network.websites) if network.websites else '  None found'}

Locations:
{chr(10).join(f"  - {location}" for location in network.locations) if network.locations else '  None found'}

{'='*80}
"""

        return ""


if __name__ == "__main__":
    # Example usage
    async def main():
        async with SocialProfileAggregator() as spa:
            # Search by username
            network = await spa.search_username("johndoe")
            print(spa.export_network(network, format='text'))

            # Generate network graph
            graph = spa.generate_network_graph(network)
            print(json.dumps(graph, indent=2))

            # Search by name
            network2 = await spa.search_name("John Doe")
            print(spa.export_network(network2, format='json'))

    asyncio.run(main())

#!/usr/bin/env python3
"""
Russian Forum Crawler - Monitor Russian forums for target mentions
Apollo Platform - Regional Intelligence Module
"""

import requests
from bs4 import BeautifulSoup
from typing import List, Dict
from datetime import datetime
import time


class RussianForums:
    """
    Crawl and monitor Russian forums for keywords and mentions
    """
    
    def __init__(self):
        self.forums = {
            'bits_media': {
                'url': 'https://forum.bits.media',
                'type': 'crypto',
                'encoding': 'utf-8'
            },
            'bitcointalk_ru': {
                'url': 'https://bitcointalk.org/index.php?board=235.0',
                'type': 'crypto',
                'encoding': 'utf-8'
            },
            'ru_board': {
                'url': 'https://forum.ru-board.com',
                'type': 'general',
                'encoding': 'windows-1251'
            },
            'woman_ru': {
                'url': 'https://www.woman.ru/forum',
                'type': 'social',
                'encoding': 'utf-8'
            }
        }
    
    def crawl(self, params: Dict) -> List[Dict]:
        """
        Crawl forums for keyword mentions
        
        Args:
            params: Crawl parameters with keywords, timeframe, alert settings
            
        Returns:
            List of forum mentions with context
        """
        mentions = []
        
        keywords = params.get('keywords', [])
        forums_to_crawl = params.get('forums', self.forums.keys())
        
        for forum_key in forums_to_crawl:
            if forum_key not in self.forums:
                continue
                
            forum = self.forums[forum_key]
            print(f"Crawling {forum['url']}...")
            
            try:
                # Search forum for keywords
                forum_mentions = self._search_forum(forum, keywords)
                mentions.extend(forum_mentions)
            except Exception as e:
                print(f"Error crawling {forum_key}: {e}")
        
        # Alert on mentions
        if params.get('alert_on_mention') and mentions:
            self._alert_mentions(mentions, params.get('case_id'))
        
        # Feed to Apollo
        self._feed_to_apollo(mentions, params.get('case_id'))
        
        return mentions
    
    def _search_forum(self, forum: Dict, keywords: List[str]) -> List[Dict]:
        """Search specific forum for keywords"""
        mentions = []
        
        for keyword in keywords:
            try:
                # Construct search URL (forum-specific)
                search_url = f"{forum['url']}/search.php?keywords={keyword}"
                
                response = requests.get(search_url, timeout=30)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Parse results (implementation depends on forum structure)
                results = self._parse_forum_results(soup, forum)
                
                for result in results:
                    mentions.append({
                        'forum': forum['url'],
                        'forum_type': forum['type'],
                        'keyword': keyword,
                        'title': result.get('title'),
                        'author': result.get('author'),
                        'date': result.get('date'),
                        'url': result.get('url'),
                        'excerpt': result.get('excerpt'),
                        'found_at': datetime.now().isoformat()
                    })
                    
            except Exception as e:
                print(f"Error searching for '{keyword}' in {forum['url']}: {e}")
        
        return mentions
    
    def _parse_forum_results(self, soup, forum: Dict) -> List[Dict]:
        """Parse forum search results"""
        results = []
        
        # Generic parsing - customize per forum
        search_results = soup.find_all('div', class_='search-result')
        
        for result in search_results:
            try:
                results.append({
                    'title': result.find('a', class_='title').text if result.find('a', class_='title') else '',
                    'author': result.find('span', class_='author').text if result.find('span', class_='author') else '',
                    'date': result.find('span', class_='date').text if result.find('span', class_='date') else '',
                    'url': result.find('a', class_='title')['href'] if result.find('a', class_='title') else '',
                    'excerpt': result.find('div', class_='excerpt').text if result.find('div', class_='excerpt') else ''
                })
            except Exception as e:
                continue
        
        return results
    
    def _alert_mentions(self, mentions: List[Dict], case_id: Optional[str]):
        """Alert on forum mentions"""
        for mention in mentions:
            try:
                from apollo.alerts import IntelligenceAlert
                
                alert = IntelligenceAlert()
                alert.send({
                    'type': 'FORUM_MENTION',
                    'source': mention['forum'],
                    'keyword': mention['keyword'],
                    'title': mention['title'],
                    'url': mention['url'],
                    'excerpt': mention['excerpt'],
                    'case_id': case_id,
                    'priority': 'MEDIUM'
                })
            except Exception as e:
                print(f"Alert error: {e}")
    
    def _feed_to_apollo(self, mentions: List[Dict], case_id: Optional[str]):
        """Feed to Apollo intelligence fusion"""
        try:
            from apollo.intelligence import IntelligenceFusion
            
            fusion = IntelligenceFusion()
            fusion.ingest({
                'source': 'russian-forums',
                'type': 'regional-osint',
                'data': mentions,
                'case_id': case_id,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"Warning: Could not feed to Apollo: {e}")
    
    def continuous_monitor(self, keywords: List[str], interval: int = 3600):
        """
        Continuously monitor forums for keywords
        
        Args:
            keywords: Keywords to monitor
            interval: Check interval in seconds (default 1 hour)
        """
        print(f"Starting continuous forum monitoring (interval: {interval}s)")
        
        while True:
            try:
                mentions = self.crawl({
                    'keywords': keywords,
                    'alert_on_mention': True
                })
                
                if mentions:
                    print(f"Found {len(mentions)} new mentions")
                
                time.sleep(interval)
            except KeyboardInterrupt:
                print("Monitoring stopped")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(interval)


if __name__ == "__main__":
    # Example: Monitor for Ignatova mentions
    forums = RussianForums()
    
    # One-time crawl
    mentions = forums.crawl({
        'keywords': ['onecoin', 'ruja', 'ignatova', 'криптокоролева'],
        'forums': ['bits_media', 'bitcointalk_ru'],
        'timeframe': '2017-2024',
        'alert_on_mention': True,
        'case_id': 'HVT-CRYPTO-2026-001'
    })
    
    print(f"Russian forum crawl complete: {len(mentions)} mentions found")
    
    # Or start continuous monitoring
    # forums.continuous_monitor(['onecoin', 'ruja', 'ignatova'], interval=3600)

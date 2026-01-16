#!/usr/bin/env python3
"""
Bulgarian News Scraper - Monitor Bulgarian media for target mentions
Apollo Platform - Regional Intelligence Module
"""

import requests
from bs4 import BeautifulSoup
import feedparser
from typing import List, Dict
from datetime import datetime


class BulgarianNews:
    """
    Monitor Bulgarian news sources for mentions and intelligence
    """
    
    def __init__(self):
        self.sources = {
            'dnevnik': {
                'url': 'https://www.dnevnik.bg',
                'rss': 'https://www.dnevnik.bg/rss/',
                'type': 'general_news'
            },
            'mediapool': {
                'url': 'https://www.mediapool.bg',
                'rss': 'https://www.mediapool.bg/rss/',
                'type': 'general_news'
            },
            'capital': {
                'url': 'https://www.capital.bg',
                'rss': 'https://www.capital.bg/rss/',
                'type': 'business_news'
            },
            'investor': {
                'url': 'https://www.investor.bg',
                'rss': 'https://www.investor.bg/rss/',
                'type': 'financial_news'
            },
            'bivol': {
                'url': 'https://bivol.bg',
                'rss': 'https://bivol.bg/feed',
                'type': 'investigative'
            }
        }
    
    def monitor(self, params: Dict) -> List[Dict]:
        """
        Monitor Bulgarian news sources
        
        Args:
            params: Monitoring parameters (keywords, sources, languages)
            
        Returns:
            List of relevant articles with sentiment analysis
        """
        articles = []
        
        keywords = params.get('keywords', [])
        sources = params.get('sources', self.sources.keys())
        
        for source_key in sources:
            if source_key not in self.sources:
                continue
            
            source = self.sources[source_key]
            print(f"Monitoring {source['url']}...")
            
            try:
                # Check RSS feed
                source_articles = self._check_rss(source['rss'], keywords)
                
                # Enhance with full article text
                for article in source_articles:
                    article['source'] = source_key
                    article['source_type'] = source['type']
                    article['full_text'] = self._fetch_article_text(article['link'])
                    
                    # Sentiment analysis
                    if params.get('sentiment_analysis'):
                        article['sentiment'] = self._analyze_sentiment(article['full_text'])
                    
                    articles.append(article)
                
            except Exception as e:
                print(f"Error monitoring {source_key}: {e}")
        
        # Alert on mentions
        if params.get('alert_on_mention') and articles:
            self._alert_articles(articles, params.get('case_id'))
        
        # Feed to Apollo
        self._feed_to_apollo(articles, params.get('case_id'))
        
        return articles
    
    def _check_rss(self, rss_url: str, keywords: List[str]) -> List[Dict]:
        """Check RSS feed for keywords"""
        articles = []
        
        try:
            feed = feedparser.parse(rss_url)
            
            for entry in feed.entries:
                # Check if any keyword in title or description
                text = f"{entry.get('title', '')} {entry.get('description', '')}".lower()
                
                for keyword in keywords:
                    if keyword.lower() in text:
                        articles.append({
                            'title': entry.get('title'),
                            'link': entry.get('link'),
                            'published': entry.get('published'),
                            'description': entry.get('description'),
                            'keyword_matched': keyword
                        })
                        break
        except Exception as e:
            print(f"RSS feed error: {e}")
        
        return articles
    
    def _fetch_article_text(self, url: str) -> str:
        """Fetch full article text"""
        try:
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract article text (customize per site)
            article_body = soup.find('article') or soup.find('div', class_='article-body')
            
            if article_body:
                return article_body.get_text(strip=True)
            return ""
        except Exception as e:
            return ""
    
    def _analyze_sentiment(self, text: str) -> str:
        """Analyze sentiment of article"""
        # Simple sentiment analysis
        # Could integrate with Apollo AI for better analysis
        
        negative_words = ['fraud', 'scam', 'fugitive', 'wanted', 'criminal']
        positive_words = ['successful', 'entrepreneur', 'innovative']
        
        text_lower = text.lower()
        neg_count = sum(word in text_lower for word in negative_words)
        pos_count = sum(word in text_lower for word in positive_words)
        
        if neg_count > pos_count:
            return 'negative'
        elif pos_count > neg_count:
            return 'positive'
        return 'neutral'
    
    def _alert_articles(self, articles: List[Dict], case_id: str):
        """Alert on relevant articles"""
        for article in articles:
            try:
                from apollo.alerts import IntelligenceAlert
                
                alert = IntelligenceAlert()
                alert.send({
                    'type': 'NEWS_MENTION',
                    'source': article['source'],
                    'title': article['title'],
                    'url': article['link'],
                    'sentiment': article.get('sentiment', 'unknown'),
                    'case_id': case_id,
                    'priority': 'MEDIUM'
                })
            except Exception as e:
                print(f"Alert error: {e}")
    
    def _feed_to_apollo(self, articles: List[Dict], case_id: str):
        """Feed to Apollo intelligence"""
        try:
            from apollo.intelligence import IntelligenceFusion
            
            fusion = IntelligenceFusion()
            fusion.ingest({
                'source': 'bulgarian-news',
                'type': 'regional-news',
                'data': articles,
                'case_id': case_id,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"Warning: Could not feed to Apollo: {e}")


if __name__ == "__main__":
    # Example: Monitor for Ignatova
    news = BulgarianNews()
    
    articles = news.monitor({
        'sources': ['dnevnik', 'mediapool', 'capital', 'investor', 'bivol'],
        'keywords': ['Ружа Игнатова', 'OneCoin', 'Ruja Ignatova', 'Криптокралица'],
        'languages': ['bulgarian', 'english'],
        'sentiment_analysis': True,
        'alert_on_mention': True,
        'case_id': 'HVT-CRYPTO-2026-001'
    })
    
    print(f"Bulgarian news monitoring: {len(articles)} articles found")

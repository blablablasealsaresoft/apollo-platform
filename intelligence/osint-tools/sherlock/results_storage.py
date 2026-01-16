"""
Results Storage for Sherlock
Stores search results in Elasticsearch
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from dataclasses import asdict
from .sherlock_engine import UsernameResult

logger = logging.getLogger(__name__)


class SherlockResultsStorage:
    """
    Store and retrieve Sherlock search results in Elasticsearch
    """

    def __init__(
        self,
        es_client: Optional[Elasticsearch] = None,
        es_hosts: Optional[List[str]] = None,
        index_prefix: str = 'apollo-sherlock'
    ):
        """
        Initialize results storage

        Args:
            es_client: Existing Elasticsearch client
            es_hosts: Elasticsearch hosts (if client not provided)
            index_prefix: Prefix for Elasticsearch indices
        """
        if es_client:
            self.es = es_client
        else:
            hosts = es_hosts or ['http://localhost:9200']
            self.es = Elasticsearch(hosts)

        self.index_prefix = index_prefix
        self._ensure_indices()

    def _ensure_indices(self):
        """Create Elasticsearch indices if they don't exist"""
        # Results index
        results_index = f"{self.index_prefix}-results"
        if not self.es.indices.exists(index=results_index):
            self.es.indices.create(
                index=results_index,
                body={
                    "settings": {
                        "number_of_shards": 2,
                        "number_of_replicas": 1
                    },
                    "mappings": {
                        "properties": {
                            "username": {"type": "keyword"},
                            "platform": {"type": "keyword"},
                            "url": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "confidence_score": {"type": "float"},
                            "response_time_ms": {"type": "integer"},
                            "http_status": {"type": "integer"},
                            "timestamp": {"type": "date"},
                            "metadata": {"type": "object", "enabled": False}
                        }
                    }
                }
            )
            logger.info(f"Created index: {results_index}")

        # Search history index
        history_index = f"{self.index_prefix}-searches"
        if not self.es.indices.exists(index=history_index):
            self.es.indices.create(
                index=history_index,
                body={
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1
                    },
                    "mappings": {
                        "properties": {
                            "usernames": {"type": "keyword"},
                            "platforms": {"type": "keyword"},
                            "total_results": {"type": "integer"},
                            "found_results": {"type": "integer"},
                            "timestamp": {"type": "date"},
                            "duration_seconds": {"type": "float"}
                        }
                    }
                }
            )
            logger.info(f"Created index: {history_index}")

    def store_results(
        self,
        results: List[UsernameResult],
        search_id: Optional[str] = None
    ) -> int:
        """
        Store username search results

        Args:
            results: List of UsernameResult objects
            search_id: Optional search ID to group results

        Returns:
            Number of results stored
        """
        if not results:
            return 0

        index = f"{self.index_prefix}-results"

        # Prepare bulk documents
        actions = []
        for result in results:
            doc = asdict(result)
            doc['timestamp'] = result.timestamp.isoformat()
            if search_id:
                doc['search_id'] = search_id

            actions.append({
                "_index": index,
                "_source": doc
            })

        # Bulk insert
        success, failed = helpers.bulk(
            self.es,
            actions,
            raise_on_error=False
        )

        logger.info(
            f"Stored {success} results, {len(failed)} failed"
        )

        return success

    def store_search_history(
        self,
        usernames: List[str],
        platforms: Optional[List[str]],
        total_results: int,
        found_results: int,
        duration_seconds: float,
        search_id: Optional[str] = None
    ) -> str:
        """
        Store search history

        Args:
            usernames: List of usernames searched
            platforms: List of platforms searched
            total_results: Total number of results
            found_results: Number of found results
            duration_seconds: Search duration
            search_id: Optional search ID

        Returns:
            Document ID
        """
        index = f"{self.index_prefix}-searches"

        doc = {
            'usernames': usernames,
            'platforms': platforms,
            'total_results': total_results,
            'found_results': found_results,
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration_seconds
        }

        if search_id:
            result = self.es.index(index=index, id=search_id, body=doc)
        else:
            result = self.es.index(index=index, body=doc)

        return result['_id']

    def search_by_username(
        self,
        username: str,
        status: Optional[str] = None,
        platforms: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search results by username

        Args:
            username: Username to search for
            status: Filter by status ('found', 'not_found', etc.)
            platforms: Filter by platforms
            limit: Maximum results to return

        Returns:
            List of result documents
        """
        index = f"{self.index_prefix}-results"

        query = {
            "bool": {
                "must": [
                    {"term": {"username": username}}
                ]
            }
        }

        if status:
            query["bool"]["must"].append({"term": {"status": status}})

        if platforms:
            query["bool"]["must"].append(
                {"terms": {"platform": platforms}}
            )

        response = self.es.search(
            index=index,
            body={
                "query": query,
                "size": limit,
                "sort": [{"timestamp": "desc"}]
            }
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def search_by_platform(
        self,
        platform: str,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search results by platform

        Args:
            platform: Platform name
            status: Filter by status
            limit: Maximum results to return

        Returns:
            List of result documents
        """
        index = f"{self.index_prefix}-results"

        query = {
            "bool": {
                "must": [
                    {"term": {"platform": platform}}
                ]
            }
        }

        if status:
            query["bool"]["must"].append({"term": {"status": status}})

        response = self.es.search(
            index=index,
            body={
                "query": query,
                "size": limit,
                "sort": [{"timestamp": "desc"}]
            }
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def get_username_summary(self, username: str) -> Dict[str, Any]:
        """
        Get summary of username across all platforms

        Args:
            username: Username to summarize

        Returns:
            Dictionary with summary statistics
        """
        index = f"{self.index_prefix}-results"

        response = self.es.search(
            index=index,
            body={
                "query": {"term": {"username": username}},
                "size": 0,
                "aggs": {
                    "by_status": {
                        "terms": {"field": "status"}
                    },
                    "platforms_found": {
                        "filter": {"term": {"status": "found"}},
                        "aggs": {
                            "platforms": {
                                "terms": {"field": "platform", "size": 1000}
                            }
                        }
                    },
                    "avg_confidence": {
                        "filter": {"term": {"status": "found"}},
                        "aggs": {
                            "score": {"avg": {"field": "confidence_score"}}
                        }
                    }
                }
            }
        )

        aggs = response["aggregations"]

        status_counts = {
            bucket["key"]: bucket["doc_count"]
            for bucket in aggs["by_status"]["buckets"]
        }

        platforms_found = [
            bucket["key"]
            for bucket in aggs["platforms_found"]["platforms"]["buckets"]
        ]

        avg_confidence = (
            aggs["avg_confidence"]["score"]["value"]
            if aggs["avg_confidence"]["doc_count"] > 0
            else 0.0
        )

        return {
            "username": username,
            "total_searches": response["hits"]["total"]["value"],
            "status_counts": status_counts,
            "platforms_found": platforms_found,
            "platform_count": len(platforms_found),
            "average_confidence": avg_confidence
        }

    def get_search_history(
        self,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get recent search history

        Args:
            limit: Number of searches to return

        Returns:
            List of search history documents
        """
        index = f"{self.index_prefix}-searches"

        response = self.es.search(
            index=index,
            body={
                "size": limit,
                "sort": [{"timestamp": "desc"}]
            }
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def delete_old_results(self, days: int = 90) -> int:
        """
        Delete results older than specified days

        Args:
            days: Number of days to keep

        Returns:
            Number of documents deleted
        """
        index = f"{self.index_prefix}-results"

        response = self.es.delete_by_query(
            index=index,
            body={
                "query": {
                    "range": {
                        "timestamp": {
                            "lt": f"now-{days}d"
                        }
                    }
                }
            }
        )

        deleted = response.get("deleted", 0)
        logger.info(f"Deleted {deleted} old results")

        return deleted

    def get_platform_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about platform coverage

        Returns:
            Dictionary with platform statistics
        """
        index = f"{self.index_prefix}-results"

        response = self.es.search(
            index=index,
            body={
                "size": 0,
                "aggs": {
                    "platforms": {
                        "terms": {"field": "platform", "size": 1000},
                        "aggs": {
                            "by_status": {
                                "terms": {"field": "status"}
                            },
                            "avg_confidence": {
                                "avg": {"field": "confidence_score"}
                            },
                            "avg_response_time": {
                                "avg": {"field": "response_time_ms"}
                            }
                        }
                    }
                }
            }
        )

        platforms = {}
        for bucket in response["aggregations"]["platforms"]["buckets"]:
            platform_name = bucket["key"]
            platforms[platform_name] = {
                "total_searches": bucket["doc_count"],
                "status_breakdown": {
                    b["key"]: b["doc_count"]
                    for b in bucket["by_status"]["buckets"]
                },
                "avg_confidence": bucket["avg_confidence"]["value"],
                "avg_response_time_ms": bucket["avg_response_time"]["value"]
            }

        return {
            "total_platforms": len(platforms),
            "platforms": platforms
        }

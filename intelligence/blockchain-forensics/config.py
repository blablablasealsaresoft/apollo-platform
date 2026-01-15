"""
Configuration management for blockchain forensics platform
"""

import os
from typing import Dict, List, Optional
from pydantic import BaseSettings, Field


class BlockchainConfig(BaseSettings):
    """Blockchain forensics configuration"""

    # Database connections
    TIMESCALEDB_HOST: str = Field(default="localhost", env="TIMESCALEDB_HOST")
    TIMESCALEDB_PORT: int = Field(default=5432, env="TIMESCALEDB_PORT")
    TIMESCALEDB_USER: str = Field(default="apollo", env="TIMESCALEDB_USER")
    TIMESCALEDB_PASSWORD: str = Field(default="", env="TIMESCALEDB_PASSWORD")
    TIMESCALEDB_DB: str = Field(default="apollo_blockchain", env="TIMESCALEDB_DB")

    NEO4J_URI: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    NEO4J_USER: str = Field(default="neo4j", env="NEO4J_USER")
    NEO4J_PASSWORD: str = Field(default="", env="NEO4J_PASSWORD")

    REDIS_HOST: str = Field(default="localhost", env="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, env="REDIS_PORT")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")

    ELASTICSEARCH_HOST: str = Field(default="localhost", env="ELASTICSEARCH_HOST")
    ELASTICSEARCH_PORT: int = Field(default=9200, env="ELASTICSEARCH_PORT")

    # API Keys for blockchain explorers
    BLOCKCHAIN_INFO_API_KEY: str = Field(default="", env="BLOCKCHAIN_INFO_API_KEY")
    BLOCKCYPHER_API_KEY: str = Field(default="", env="BLOCKCYPHER_API_KEY")
    ETHERSCAN_API_KEY: str = Field(default="", env="ETHERSCAN_API_KEY")
    BSCSCAN_API_KEY: str = Field(default="", env="BSCSCAN_API_KEY")
    POLYGONSCAN_API_KEY: str = Field(default="", env="POLYGONSCAN_API_KEY")
    SNOWTRACE_API_KEY: str = Field(default="", env="SNOWTRACE_API_KEY")
    ALCHEMY_API_KEY: str = Field(default="", env="ALCHEMY_API_KEY")

    # Rate limiting
    API_RATE_LIMIT: int = Field(default=5, env="API_RATE_LIMIT")  # requests per second
    API_RATE_LIMIT_PERIOD: int = Field(default=1, env="API_RATE_LIMIT_PERIOD")  # seconds

    # Cache settings
    CACHE_TTL: int = Field(default=3600, env="CACHE_TTL")  # 1 hour
    CACHE_ENABLED: bool = Field(default=True, env="CACHE_ENABLED")

    # OneCoin specific settings
    ONECOIN_KNOWN_ADDRESSES: List[str] = Field(default_factory=list)
    RUJA_IGNATOVA_ADDRESSES: List[str] = Field(default_factory=list)

    # Monitoring settings
    ALERT_WEBHOOK_URL: Optional[str] = Field(default=None, env="ALERT_WEBHOOK_URL")
    MONITORING_ENABLED: bool = Field(default=True, env="MONITORING_ENABLED")

    # AML settings
    AML_HIGH_RISK_THRESHOLD: int = Field(default=70, env="AML_HIGH_RISK_THRESHOLD")
    AML_MEDIUM_RISK_THRESHOLD: int = Field(default=40, env="AML_MEDIUM_RISK_THRESHOLD")

    # Clustering settings
    CLUSTER_MIN_CONFIDENCE: float = Field(default=0.7, env="CLUSTER_MIN_CONFIDENCE")

    # Transaction tracing
    MAX_TRACE_DEPTH: int = Field(default=10, env="MAX_TRACE_DEPTH")
    MAX_TRACE_HOPS: int = Field(default=100, env="MAX_TRACE_HOPS")

    class Config:
        env_file = ".env"
        case_sensitive = True


# Global config instance
config = BlockchainConfig()


# Known exchange addresses (sample - expand this list)
KNOWN_EXCHANGES: Dict[str, List[str]] = {
    "binance": [
        "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",  # Binance cold wallet
        "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",  # Binance old wallet
    ],
    "coinbase": [
        "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97",
    ],
    "kraken": [
        "bc1qjasf9z3h7w3jspkhtgatgpyvvzgpa2wwd2lr0eh5tx44reyn2k7sfc27a4",
    ],
    "bitfinex": [
        "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97",
    ],
}

# Known mixer/tumbler addresses
KNOWN_MIXERS: Dict[str, List[str]] = {
    "wasabi": [],
    "samourai": [],
    "tornado_cash": [
        "0x8589427373D6D84E98730D7795D8f6f8731FDA16",  # Tornado Cash 0.1 ETH
        "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",  # Tornado Cash 1 ETH
        "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",  # Tornado Cash 10 ETH
        "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Cash 100 ETH
    ],
    "coinjoin": [],
}

# Known ransomware addresses (sample)
KNOWN_RANSOMWARE: Dict[str, List[str]] = {
    "wannacry": [
        "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
        "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
        "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
    ],
    "ryuk": [],
    "conti": [],
}


def get_timescaledb_url() -> str:
    """Get TimescaleDB connection URL"""
    return (
        f"postgresql://{config.TIMESCALEDB_USER}:{config.TIMESCALEDB_PASSWORD}@"
        f"{config.TIMESCALEDB_HOST}:{config.TIMESCALEDB_PORT}/{config.TIMESCALEDB_DB}"
    )


def get_neo4j_config() -> Dict[str, str]:
    """Get Neo4j configuration"""
    return {
        "uri": config.NEO4J_URI,
        "user": config.NEO4J_USER,
        "password": config.NEO4J_PASSWORD,
    }


def get_redis_config() -> Dict[str, any]:
    """Get Redis configuration"""
    return {
        "host": config.REDIS_HOST,
        "port": config.REDIS_PORT,
        "db": config.REDIS_DB,
    }

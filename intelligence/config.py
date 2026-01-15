"""
Configuration Management for Apollo Intelligence
Loads settings from environment variables
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""

    # Environment
    environment: str = Field(default='development', env='ENVIRONMENT')
    debug: bool = Field(default=False, env='DEBUG')
    log_level: str = Field(default='INFO', env='LOG_LEVEL')

    # API Server
    api_host: str = Field(default='0.0.0.0', env='API_HOST')
    api_port: int = Field(default=8000, env='API_PORT')
    api_workers: int = Field(default=4, env='API_WORKERS')

    # Elasticsearch
    elasticsearch_hosts: List[str] = Field(
        default=['http://localhost:9200'],
        env='ELASTICSEARCH_HOSTS'
    )
    elasticsearch_username: Optional[str] = Field(None, env='ELASTICSEARCH_USERNAME')
    elasticsearch_password: Optional[str] = Field(None, env='ELASTICSEARCH_PASSWORD')

    # Redis
    redis_host: str = Field(default='localhost', env='REDIS_HOST')
    redis_port: int = Field(default=6379, env='REDIS_PORT')
    redis_password: Optional[str] = Field(None, env='REDIS_PASSWORD')
    redis_db: int = Field(default=0, env='REDIS_DB')

    # RabbitMQ
    rabbitmq_host: str = Field(default='localhost', env='RABBITMQ_HOST')
    rabbitmq_port: int = Field(default=5672, env='RABBITMQ_PORT')
    rabbitmq_user: str = Field(default='guest', env='RABBITMQ_USER')
    rabbitmq_password: str = Field(default='guest', env='RABBITMQ_PASSWORD')

    # PostgreSQL
    postgres_host: str = Field(default='localhost', env='POSTGRES_HOST')
    postgres_port: int = Field(default=5432, env='POSTGRES_PORT')
    postgres_db: str = Field(default='apollo', env='POSTGRES_DB')
    postgres_user: str = Field(default='apollo', env='POSTGRES_USER')
    postgres_password: str = Field(default='changeme', env='POSTGRES_PASSWORD')

    # OSINT APIs
    shodan_api_key: Optional[str] = Field(None, env='SHODAN_API_KEY')
    censys_api_id: Optional[str] = Field(None, env='CENSYS_API_ID')
    censys_api_secret: Optional[str] = Field(None, env='CENSYS_API_SECRET')
    virustotal_api_key: Optional[str] = Field(None, env='VIRUSTOTAL_API_KEY')
    securitytrails_api_key: Optional[str] = Field(None, env='SECURITYTRAILS_API_KEY')
    alienvault_api_key: Optional[str] = Field(None, env='ALIENVAULT_API_KEY')

    # Breach Databases
    dehashed_api_key: Optional[str] = Field(None, env='DEHASHED_API_KEY')
    dehashed_email: Optional[str] = Field(None, env='DEHASHED_EMAIL')
    hibp_api_key: Optional[str] = Field(None, env='HIBP_API_KEY')
    snusbase_api_key: Optional[str] = Field(None, env='SNUSBASE_API_KEY')
    leakcheck_api_key: Optional[str] = Field(None, env='LEAKCHECK_API_KEY')

    # Blockchain APIs
    etherscan_api_key: Optional[str] = Field(None, env='ETHERSCAN_API_KEY')
    bscscan_api_key: Optional[str] = Field(None, env='BSCSCAN_API_KEY')
    polygonscan_api_key: Optional[str] = Field(None, env='POLYGONSCAN_API_KEY')
    blockchair_api_key: Optional[str] = Field(None, env='BLOCKCHAIR_API_KEY')
    blockcypher_token: Optional[str] = Field(None, env='BLOCKCYPHER_TOKEN')

    # Social Media APIs
    twitter_bearer_token: Optional[str] = Field(None, env='TWITTER_BEARER_TOKEN')
    facebook_access_token: Optional[str] = Field(None, env='FACEBOOK_ACCESS_TOKEN')
    telegram_bot_token: Optional[str] = Field(None, env='TELEGRAM_BOT_TOKEN')

    # Geolocation APIs
    maxmind_license_key: Optional[str] = Field(None, env='MAXMIND_LICENSE_KEY')
    ipinfo_token: Optional[str] = Field(None, env='IPINFO_TOKEN')
    twilio_account_sid: Optional[str] = Field(None, env='TWILIO_ACCOUNT_SID')
    twilio_auth_token: Optional[str] = Field(None, env='TWILIO_AUTH_TOKEN')

    # Security
    secret_key: str = Field(
        default='change-this-in-production',
        env='SECRET_KEY'
    )
    allowed_hosts: str = Field(default='*', env='ALLOWED_HOSTS')
    cors_origins: str = Field(default='*', env='CORS_ORIGINS')

    # Rate Limiting
    rate_limit_per_minute: int = Field(default=60, env='RATE_LIMIT_PER_MINUTE')
    rate_limit_per_hour: int = Field(default=1000, env='RATE_LIMIT_PER_HOUR')

    # Caching
    cache_ttl: int = Field(default=300, env='CACHE_TTL')
    cache_max_size: int = Field(default=10000, env='CACHE_MAX_SIZE')

    # Feature Flags
    enable_sherlock: bool = Field(default=True, env='ENABLE_SHERLOCK')
    enable_bbot: bool = Field(default=True, env='ENABLE_BBOT')
    enable_blockchain: bool = Field(default=True, env='ENABLE_BLOCKCHAIN')
    enable_breach_db: bool = Field(default=True, env='ENABLE_BREACH_DB')
    enable_fusion_engine: bool = Field(default=True, env='ENABLE_FUSION_ENGINE')

    # Advanced
    max_retries: int = Field(default=3, env='MAX_RETRIES')
    retry_timeout: int = Field(default=30, env='RETRY_TIMEOUT')
    circuit_breaker_threshold: int = Field(default=5, env='CIRCUIT_BREAKER_THRESHOLD')
    circuit_breaker_timeout: int = Field(default=60, env='CIRCUIT_BREAKER_TIMEOUT')
    max_concurrent_requests: int = Field(default=50, env='MAX_CONCURRENT_REQUESTS')
    data_retention_days: int = Field(default=90, env='DATA_RETENTION_DAYS')

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = False

    @property
    def redis_url(self) -> str:
        """Get Redis connection URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def rabbitmq_url(self) -> str:
        """Get RabbitMQ connection URL"""
        return f"amqp://{self.rabbitmq_user}:{self.rabbitmq_password}@{self.rabbitmq_host}:{self.rabbitmq_port}//"

    @property
    def postgres_url(self) -> str:
        """Get PostgreSQL connection URL"""
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    def get_api_keys(self) -> dict:
        """Get all configured API keys"""
        return {
            'shodan': self.shodan_api_key,
            'censys_id': self.censys_api_id,
            'censys_secret': self.censys_api_secret,
            'virustotal': self.virustotal_api_key,
            'securitytrails': self.securitytrails_api_key,
            'alienvault': self.alienvault_api_key,
            'dehashed': self.dehashed_api_key,
            'dehashed_email': self.dehashed_email,
            'hibp': self.hibp_api_key,
            'etherscan': self.etherscan_api_key,
            'bscscan': self.bscscan_api_key,
            'polygonscan': self.polygonscan_api_key,
            'twitter': self.twitter_bearer_token,
            'ipinfo': self.ipinfo_token,
        }


# Global settings instance
settings = Settings()

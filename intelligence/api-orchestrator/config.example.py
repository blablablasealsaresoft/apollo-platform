"""
API Orchestrator Configuration Template
Copy this file to config.py and add your API keys
"""

# Redis Configuration
REDIS_CONFIG = {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "password": None,
    "decode_responses": True
}

# Rate Limiting Configuration
RATE_LIMIT_CONFIG = {
    "global_requests_per_second": 1000.0,
    "global_burst_size": 5000,
    "enable_adaptive": True
}

# Caching Configuration
CACHE_CONFIG = {
    "enabled": True,
    "default_ttl": 3600,  # 1 hour
    "max_ttl": 86400,  # 24 hours
    "enable_compression": False
}

# Circuit Breaker Configuration
CIRCUIT_BREAKER_CONFIG = {
    "failure_threshold": 5,
    "success_threshold": 2,
    "timeout": 60.0
}

# API Keys - Add your keys here
API_KEYS = {
    # Social Media
    "twitter": {
        "api_key": "your_twitter_api_key",
        "api_secret": "your_twitter_api_secret",
        "bearer_token": "your_twitter_bearer_token"
    },
    "github": {
        "token": "your_github_token"
    },
    "reddit": {
        "client_id": "your_reddit_client_id",
        "client_secret": "your_reddit_client_secret"
    },

    # Blockchain/Crypto
    "coinmarketcap": {
        "api_key": "your_coinmarketcap_key"
    },
    "etherscan": {
        "api_key": "your_etherscan_key"
    },
    "moralis": {
        "api_key": "your_moralis_key"
    },

    # Geolocation
    "ipinfo": {
        "api_key": "your_ipinfo_key"
    },
    "ipstack": {
        "api_key": "your_ipstack_key"
    },
    "maxmind": {
        "account_id": "your_maxmind_account_id",
        "license_key": "your_maxmind_license_key"
    },

    # Phone/Email
    "twilio": {
        "account_sid": "your_twilio_account_sid",
        "auth_token": "your_twilio_auth_token"
    },
    "hunter": {
        "api_key": "your_hunter_api_key"
    },
    "zerobounce": {
        "api_key": "your_zerobounce_key"
    },

    # Public Records
    "fullcontact": {
        "api_key": "your_fullcontact_key"
    },
    "clearbit": {
        "api_key": "your_clearbit_key"
    },
    "pipl": {
        "api_key": "your_pipl_key"
    },

    # News/Media
    "newsapi": {
        "api_key": "your_newsapi_key"
    },
    "nytimes": {
        "api_key": "your_nytimes_key"
    },

    # Weather/Maps
    "openweather": {
        "api_key": "your_openweather_key"
    },
    "mapbox": {
        "api_key": "your_mapbox_key"
    },
    "google_maps": {
        "api_key": "your_google_maps_key"
    },

    # Finance
    "alphavantage": {
        "api_key": "your_alphavantage_key"
    },
    "finnhub": {
        "api_key": "your_finnhub_key"
    },

    # Government
    "data_gov": {
        "api_key": "your_data_gov_key"
    },

    # Security/Threat Intel
    "shodan": {
        "api_key": "your_shodan_key"
    },
    "virustotal": {
        "api_key": "your_virustotal_key"
    },
    "abuseipdb": {
        "api_key": "your_abuseipdb_key"
    },

    # Domain/DNS
    "whoisxml": {
        "api_key": "your_whoisxml_key"
    },
    "securitytrails": {
        "api_key": "your_securitytrails_key"
    },

    # AI/ML
    "openai": {
        "api_key": "your_openai_key"
    },
    "anthropic": {
        "api_key": "your_anthropic_key"
    },
    "huggingface": {
        "api_key": "your_huggingface_key"
    }
}

# Usage Quotas
API_QUOTAS = {
    "twitter": {
        "max_calls_per_day": 1000,
        "max_calls_per_month": 25000,
        "cost_per_call": 0.0,
        "max_cost_per_month": 0.0
    },
    "coinmarketcap": {
        "max_calls_per_day": 333,
        "max_calls_per_month": 10000,
        "cost_per_call": 0.01,
        "max_cost_per_month": 100.0
    },
    "ipinfo": {
        "max_calls_per_day": 1666,
        "max_calls_per_month": 50000,
        "cost_per_call": 0.0,
        "max_cost_per_month": 0.0
    },
    "hunter": {
        "max_calls_per_day": 66,
        "max_calls_per_month": 2000,
        "cost_per_call": 0.05,
        "max_cost_per_month": 100.0
    }
}

# Logging Configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "default",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": "api_orchestrator.log"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"]
    }
}

# Health Check Configuration
HEALTH_CHECK_CONFIG = {
    "enabled": True,
    "check_interval": 30.0,  # seconds
    "critical_apis": [
        "twitter",
        "github",
        "etherscan",
        "ipinfo",
        "hunter"
    ]
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    "max_concurrent_requests": 50,
    "request_timeout": 30.0,
    "connection_pool_size": 100,
    "enable_http2": False
}

# Export Configuration
EXPORT_CONFIG = {
    "enabled": True,
    "export_interval": 3600,  # 1 hour
    "export_path": "./exports/",
    "formats": ["json", "csv"]
}

/**
 * Apollo Platform - Central Configuration
 * 
 * This file contains the central configuration for the entire Apollo platform.
 * Environment-specific overrides should be placed in .env files.
 */

module.exports = {
  // Platform Metadata
  name: 'Apollo Platform',
  version: '0.1.0',
  environment: process.env.NODE_ENV || 'development',
  
  // AI Engine Configuration
  ai: {
    // AI Providers
    providers: {
      openrouter: {
        baseUrl: process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1',
        apiKey: process.env.OPENROUTER_API_KEY,
        models: {
          gpt4: 'openai/gpt-4',
          gpt4turbo: 'openai/gpt-4-turbo',
          claude: 'anthropic/claude-3-opus',
          claudeSonnet: 'anthropic/claude-3-sonnet',
          gemini: 'google/gemini-pro',
          geminiUltra: 'google/gemini-ultra'
        }
      },
      anthropic: {
        apiKey: process.env.ANTHROPIC_API_KEY,
        baseUrl: 'https://api.anthropic.com'
      },
      google: {
        apiKey: process.env.GOOGLE_AI_API_KEY,
        baseUrl: 'https://generativelanguage.googleapis.com'
      }
    },
    
    // AI Engine Configuration
    engines: {
      bugtrace: {
        enabled: true,
        maxConcurrency: 10,
        timeout: 300000, // 5 minutes
        retryAttempts: 3,
        models: {
          primary: 'claude',
          fallback: 'gpt4'
        }
      },
      villager: {
        enabled: true,
        autonomousMode: false,
        evasionTechniques: ['timing', 'obfuscation', 'stealth', 'polymorphic'],
        aiEnhancedPayloads: true
      },
      criminalBehavior: {
        enabled: true,
        modelPath: './ai-engine/criminal-behavior-ai/models',
        retraining: {
          enabled: true,
          schedule: '0 0 * * 0' // Weekly on Sunday
        }
      }
    }
  },
  
  // Intelligence Collection Configuration
  intelligence: {
    osint: {
      enabled: true,
      rateLimits: {
        requestsPerMinute: 60,
        requestsPerHour: 1000,
        requestsPerDay: 10000
      },
      sherlock: {
        sites: 4000,
        timeout: 30000,
        parallel: 50
      }
    },
    geoint: {
      enabled: true,
      feeds: ['satellite', 'surveillance', 'transportation', 'webcams'],
      webcamNetworks: {
        maxFeeds: 10000,
        refreshInterval: 300000 // 5 minutes
      }
    },
    sigint: {
      enabled: true,
      sources: ['broadcastify', 'radioreference', 'wigle'],
      monitoring: {
        realTime: true,
        recordingEnabled: true
      }
    }
  },
  
  // Red Team Configuration
  redteam: {
    c2: {
      frameworks: ['villager', 'cobalt-strike', 'havoc', 'mythic', 'sliver'],
      defaultFramework: 'villager',
      stealth: {
        enabled: true,
        level: 'high' // low, medium, high, maximum
      }
    },
    reconnaissance: {
      automation: {
        bbot: true,
        subhunterx: true,
        amass: true
      },
      subdomainTakeover: {
        enabled: true,
        monitoring: true,
        autoExploit: false // Requires manual approval
      }
    },
    opsec: {
      trafficObfuscation: true,
      attributionAvoidance: true,
      counterSurveillance: true,
      evidenceCleanup: true
    }
  },
  
  // Database Configuration
  database: {
    primary: {
      type: 'postgresql',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'apollo',
      username: process.env.DB_USER || 'apollo',
      password: process.env.DB_PASSWORD,
      pool: {
        min: 2,
        max: 10
      }
    },
    timeseries: {
      type: 'timescaledb',
      host: process.env.TIMESCALE_HOST || 'localhost',
      port: parseInt(process.env.TIMESCALE_PORT || '5433'),
      database: process.env.TIMESCALE_DB || 'apollo_ts'
    },
    graph: {
      type: 'neo4j',
      url: process.env.NEO4J_URL || 'neo4j://localhost:7687',
      username: process.env.NEO4J_USER || 'neo4j',
      password: process.env.NEO4J_PASSWORD
    },
    search: {
      type: 'elasticsearch',
      node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
      auth: {
        username: process.env.ELASTICSEARCH_USER,
        password: process.env.ELASTICSEARCH_PASSWORD
      }
    },
    cache: {
      type: 'redis',
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      ttl: 3600 // 1 hour default
    },
    vector: {
      type: process.env.VECTOR_DB_TYPE || 'weaviate',
      url: process.env.VECTOR_DB_URL || 'http://localhost:8080'
    }
  },
  
  // Service Configuration
  services: {
    authentication: {
      port: parseInt(process.env.AUTH_PORT || '3001'),
      host: process.env.AUTH_HOST || '0.0.0.0',
      jwt: {
        algorithm: 'RS256',
        expiresIn: '24h',
        refreshExpiresIn: '7d'
      },
      mfa: {
        enabled: true,
        required: ['admin', 'operator']
      }
    },
    operationManagement: {
      port: parseInt(process.env.OPS_PORT || '3002'),
      host: process.env.OPS_HOST || '0.0.0.0',
      maxConcurrentOperations: 100
    },
    intelligenceFusion: {
      port: parseInt(process.env.INTEL_PORT || '3003'),
      host: process.env.INTEL_HOST || '0.0.0.0',
      correlationThreshold: 0.7,
      realTimeProcessing: true
    },
    analytics: {
      port: parseInt(process.env.ANALYTICS_PORT || '3004'),
      host: process.env.ANALYTICS_HOST || '0.0.0.0'
    }
  },
  
  // Frontend Configuration
  frontend: {
    webConsole: {
      port: parseInt(process.env.WEB_PORT || '8080'),
      apiUrl: process.env.API_URL || 'http://localhost:3000/api',
      wsUrl: process.env.WS_URL || 'ws://localhost:3000/ws'
    },
    mobileApp: {
      apiUrl: process.env.MOBILE_API_URL || 'https://api.apollo-platform.com'
    }
  },
  
  // Security Configuration
  security: {
    encryption: {
      algorithm: 'aes-256-gcm',
      keyRotation: '30d' // Rotate keys every 30 days
    },
    rateLimiting: {
      windowMs: 900000, // 15 minutes
      max: 100, // 100 requests per window
      standardHeaders: true,
      legacyHeaders: false
    },
    cors: {
      origin: process.env.CORS_ORIGIN || '*',
      credentials: true
    },
    headers: {
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      contentSecurityPolicy: true,
      xFrameOptions: 'DENY'
    }
  },
  
  // Monitoring Configuration
  monitoring: {
    prometheus: {
      enabled: true,
      port: 9090,
      metricsPath: '/metrics'
    },
    grafana: {
      enabled: true,
      port: 3000
    },
    logging: {
      level: process.env.LOG_LEVEL || 'info',
      format: 'json',
      transports: ['console', 'file', 'elasticsearch']
    }
  },
  
  // Feature Flags
  features: {
    aiNativeC2: true,
    blockchainForensics: true,
    predictiveAnalytics: true,
    realTimeSurveillance: true,
    subdomainTakeover: true,
    darkWebMonitoring: true,
    geolocationTracking: true
  }
};

import dotenv from 'dotenv';
import Joi from 'joi';

dotenv.config();

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),

  // Database
  DB_HOST: Joi.string().default('localhost'),
  DB_PORT: Joi.number().default(5432),
  DB_NAME: Joi.string().default('apollo'),
  DB_USER: Joi.string().default('apollo_admin'),
  DB_PASSWORD: Joi.string().required(),

  // Redis
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().default(6379),

  // JWT
  JWT_SECRET: Joi.string().required(),
  JWT_ACCESS_EXPIRATION: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRATION: Joi.string().default('7d'),

  // OAuth
  GOOGLE_CLIENT_ID: Joi.string().optional(),
  GOOGLE_CLIENT_SECRET: Joi.string().optional(),
  MICROSOFT_CLIENT_ID: Joi.string().optional(),
  MICROSOFT_CLIENT_SECRET: Joi.string().optional(),
  GITHUB_CLIENT_ID: Joi.string().optional(),
  GITHUB_CLIENT_SECRET: Joi.string().optional(),

  // Elasticsearch
  ELASTICSEARCH_NODE: Joi.string().default('http://localhost:9200'),

  // Email
  SMTP_HOST: Joi.string().optional(),
  SMTP_PORT: Joi.number().default(587),
  SMTP_USER: Joi.string().optional(),
  SMTP_PASSWORD: Joi.string().optional(),
  SMTP_FROM: Joi.string().email().default('noreply@apollo-platform.com'),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: Joi.number().default(900000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),

  // CORS
  CORS_ORIGIN: Joi.string().default('*'),

  // Service URLs
  API_GATEWAY_URL: Joi.string().default('http://localhost:3000'),
  AUTH_SERVICE_URL: Joi.string().default('http://localhost:3001'),
  USER_SERVICE_URL: Joi.string().default('http://localhost:3002'),
  OPERATIONS_SERVICE_URL: Joi.string().default('http://localhost:3003'),
  INTELLIGENCE_SERVICE_URL: Joi.string().default('http://localhost:3004'),
  NOTIFICATIONS_SERVICE_URL: Joi.string().default('http://localhost:3005'),
  ANALYTICS_SERVICE_URL: Joi.string().default('http://localhost:3006'),
  SEARCH_SERVICE_URL: Joi.string().default('http://localhost:3007'),
}).unknown();

const { error, value: envVars } = envSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

export const config = {
  env: envVars.NODE_ENV as string,
  port: envVars.PORT as number,

  database: {
    host: envVars.DB_HOST as string,
    port: envVars.DB_PORT as number,
    name: envVars.DB_NAME as string,
    user: envVars.DB_USER as string,
    password: envVars.DB_PASSWORD as string,
  },

  redis: {
    host: envVars.REDIS_HOST as string,
    port: envVars.REDIS_PORT as number,
  },

  jwt: {
    secret: envVars.JWT_SECRET as string,
    accessExpiration: envVars.JWT_ACCESS_EXPIRATION as string,
    refreshExpiration: envVars.JWT_REFRESH_EXPIRATION as string,
  },

  oauth: {
    google: {
      clientId: envVars.GOOGLE_CLIENT_ID as string,
      clientSecret: envVars.GOOGLE_CLIENT_SECRET as string,
    },
    microsoft: {
      clientId: envVars.MICROSOFT_CLIENT_ID as string,
      clientSecret: envVars.MICROSOFT_CLIENT_SECRET as string,
    },
    github: {
      clientId: envVars.GITHUB_CLIENT_ID as string,
      clientSecret: envVars.GITHUB_CLIENT_SECRET as string,
    },
  },

  elasticsearch: {
    node: envVars.ELASTICSEARCH_NODE as string,
  },

  email: {
    smtp: {
      host: envVars.SMTP_HOST as string,
      port: envVars.SMTP_PORT as number,
      user: envVars.SMTP_USER as string,
      password: envVars.SMTP_PASSWORD as string,
    },
    from: envVars.SMTP_FROM as string,
  },

  rateLimit: {
    windowMs: envVars.RATE_LIMIT_WINDOW_MS as number,
    maxRequests: envVars.RATE_LIMIT_MAX_REQUESTS as number,
  },

  cors: {
    origin: envVars.CORS_ORIGIN as string,
  },

  services: {
    apiGateway: envVars.API_GATEWAY_URL as string,
    auth: envVars.AUTH_SERVICE_URL as string,
    user: envVars.USER_SERVICE_URL as string,
    operations: envVars.OPERATIONS_SERVICE_URL as string,
    intelligence: envVars.INTELLIGENCE_SERVICE_URL as string,
    notifications: envVars.NOTIFICATIONS_SERVICE_URL as string,
    analytics: envVars.ANALYTICS_SERVICE_URL as string,
    search: envVars.SEARCH_SERVICE_URL as string,
  },
};

export default config;

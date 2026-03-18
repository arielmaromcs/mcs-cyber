import dotenv from 'dotenv';
dotenv.config();

export const config = {
  // Server
  port: parseInt(process.env.PORT || '3001'),
  host: process.env.HOST || '0.0.0.0',
  nodeEnv: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || 'info',

  // Database
  databaseUrl: process.env.DATABASE_URL || 'postgresql://mchallenge:mchallenge@localhost:5432/mchallenge',

  // Redis
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

  // JWT
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-me',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',

  // CORS
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',

  // External APIs
  nmap: {
    apiUrl: process.env.NMAP_API_URL || 'http://45.79.208.66:8888/nmap',
    apiKey: process.env.NMAP_API_KEY || '',
  },
  shodan: { apiKey: process.env.SHODAN_API_KEY || '' },
  abuseipdb: { apiKey: process.env.ABUSEIPDB_API_KEY || '' },
  whois: { apiKey: process.env.WHOIS_API_KEY || '' },

  // LLM
  llm: {
    provider: process.env.LLM_PROVIDER || 'local',   // openai | anthropic | local
    apiKey: process.env.LLM_API_KEY || '',
    model: process.env.LLM_MODEL || 'gpt-4o',
    baseUrl: process.env.LLM_BASE_URL || 'https://api.openai.com/v1',
  },

  // Email
  email: {
    provider: process.env.EMAIL_PROVIDER || 'smtp',
    smtp: {
      host: process.env.SMTP_HOST || '',
      port: parseInt(process.env.SMTP_PORT || '587'),
      user: process.env.SMTP_USER || '',
      password: process.env.SMTP_PASSWORD || '',
      fromEmail: process.env.SMTP_FROM_EMAIL || 'noreply@mchallenge.io',
      fromName: process.env.SMTP_FROM_NAME || 'M-Challenge Scanner',
    },
    microsoftGraph: {
      tenantId: process.env.MS_TENANT_ID || '',
      clientId: process.env.MS_CLIENT_ID || '',
      clientSecret: process.env.MS_CLIENT_SECRET || '',
      fromEmail: process.env.MS_FROM_EMAIL || '',
    },
  },

  // Stripe
  stripe: {
    secretKey: process.env.STRIPE_SECRET_KEY || '',
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
    webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
    proPriceId: process.env.STRIPE_PRO_PRICE_ID || '',
  },

  // Storage
  storage: {
    provider: process.env.STORAGE_PROVIDER || 'local',
    localPath: process.env.STORAGE_LOCAL_PATH || './uploads',
    s3: {
      bucket: process.env.S3_BUCKET || '',
      region: process.env.S3_REGION || '',
      accessKey: process.env.S3_ACCESS_KEY || '',
      secretKey: process.env.S3_SECRET_KEY || '',
      endpoint: process.env.S3_ENDPOINT || '',
    },
  },

  // Rate Limiting
  rateLimit: {
    max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
  },

  // Guest
  guestMaxScans: parseInt(process.env.GUEST_MAX_SCANS || '5'),
} as const;

export type Config = typeof config;

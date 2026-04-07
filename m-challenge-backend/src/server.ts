import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { config } from './config/env';
import { prisma } from './config/database';

// Route modules
import { authRoutes } from './api/routes/auth';
import { webScanRoutes } from './api/routes/webScan';
import { emailScanRoutes } from './api/routes/emailScan';
import { threatIntelRoutes } from './api/routes/threatIntel';
import { mitreRoutes } from './api/routes/mitre';
import { scheduleRoutes } from './api/routes/schedules';
import { adminRoutes } from './api/routes/admin';
import { scanDataRoutes } from './api/routes/scanData';
import { tlsScanRoutes } from './api/routes/tlsScan';
import { clientRoutes } from './api/routes/clients';
import { nucleiRoutes } from './api/routes/nuclei';
import { pentestRoutes } from './api/routes/pentest';
import { fullScanRoutes } from './api/routes/fullScan';
import { cveRoutes } from './api/routes/cve';
import { exploitRoutes } from './api/routes/exploit';
import { initScheduler } from './jobs/scheduler';

const app = Fastify({
  logger: {
    level: config.logLevel,
    transport: config.nodeEnv === 'development' ? { target: 'pino-pretty' } : undefined,
  },
});

// ---- Plugins ----
app.register(cors, { origin: true, credentials: true });
app.register(jwt, { secret: config.jwtSecret });

// ---- Auth decorator ----
app.decorate('authenticate', async function (request: any, reply: any) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.status(401).send({ error: 'Unauthorized' });
  }
});

app.decorate('optionalAuth', async function (request: any, reply: any) {
  try {
    await request.jwtVerify();
  } catch {
    // Guest user - no token, that's ok
    request.user = null;
  }
});

app.decorate('requireAdmin', async function (request: any, reply: any) {
  try {
    await request.jwtVerify();
    if (request.user?.role !== 'ADMIN') {
      reply.status(403).send({ error: 'Admin access required' });
    }
  } catch {
    reply.status(401).send({ error: 'Unauthorized' });
  }
});

// ---- Health check ----
app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' }));
app.get('/api/health', async () => ({ status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' }));

// ---- Register API routes ----
app.register(authRoutes, { prefix: '/api/auth' });
app.register(tlsScanRoutes, { prefix: '/api/tls-scan' });
app.register(clientRoutes, { prefix: '/api/clients' });
app.register(nucleiRoutes, { prefix: '/api/nuclei' });
app.register(pentestRoutes, { prefix: '/api/pentest' });
app.register(fullScanRoutes, { prefix: '/api/full-scan' });
app.register(cveRoutes, { prefix: '/api' });
app.register(exploitRoutes, { prefix: '/api/exploit' });
app.register(webScanRoutes, { prefix: '/api/web-scan' });
app.register(emailScanRoutes, { prefix: '/api/email-scan' });
app.register(threatIntelRoutes, { prefix: '/api/threat-intel' });
app.register(mitreRoutes, { prefix: '/api/mitre' });
app.register(scheduleRoutes, { prefix: '/api/schedules' });
app.register(adminRoutes, { prefix: '/api/admin' });
app.register(scanDataRoutes, { prefix: '/api/data' });

// ---- Start ----
async function start() {
  try {
    // Test DB connection
    await prisma.$connect();
    app.log.info('Database connected');

    // Start cron scheduler for recurring scans
    initScheduler();

    await app.listen({ port: config.port, host: config.host });
    app.log.info(`M-Challenge Backend running on http://${config.host}:${config.port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

start();

export default app;

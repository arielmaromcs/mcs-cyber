import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../config/database';
import { WebScannerService } from '../../services/scanning/webScanner';
import { ExploitabilityService } from '../../services/analysis/exploitability';
import { config } from '../../config/env';

const startScanSchema = z.object({
  url: z.string().min(3),
  options: z.object({
    scan_profile: z.enum(['quick', 'standard', 'deep', 'extreme']).default('standard'),
    max_pages: z.number().min(1).max(200).default(30),
    max_depth: z.number().min(1).max(10).default(3),
    respect_robots: z.boolean().default(true),
  }).optional(),
  discover_subdomains: z.boolean().default(true),
  guest_scans_used: z.number().default(0),
});

export async function webScanRoutes(app: FastifyInstance) {
  // POST /api/web-scan/start
  app.post('/start', { preHandler: [(app as any).optionalAuth] }, async (request, reply) => {
    const body = startScanSchema.parse(request.body);
    const user = (request as any).user;

    // Guest limit check
    if (!user && body.guest_scans_used >= config.guestMaxScans) {
      return reply.status(403).send({ error: 'Guest scan limit reached. Please sign in.' });
    }

    // Authenticated user quota check
    if (user) {
      const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
      if (dbUser && dbUser.role !== 'ADMIN' && dbUser.scansRemaining <= 0) {
        return reply.status(403).send({ error: 'Scan quota exhausted. Please upgrade.' });
      }
    }

    // Normalize URL
    let targetUrl = body.url.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = `https://${targetUrl}`;
    }

    // Extract domain
    let domain: string;
    try {
      const u = new URL(targetUrl);
      domain = u.hostname.replace(/^www\./, '');
    } catch {
      return reply.status(400).send({ error: 'Invalid URL' });
    }

    // Check for existing running scan on same domain
    const existingRunning = await prisma.webScan.findFirst({
      where: { domain, status: 'RUNNING' },
      select: { id: true },
    });
    if (existingRunning) {
      return { scan_id: existingRunning.id, status: 'already_running' };
    }

    // Create scan entity
    const scan = await prisma.webScan.create({
      data: {
        userId: user?.id || null,
        url: targetUrl,
        domain,
        status: 'RUNNING',
        progress: 0,
        stage: 'DISCOVERY',
        scanProfile: body.options?.scan_profile || 'standard',
        isParentScan: body.discover_subdomains,
        findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        discovery: { hosts_discovered: [], paths_discovered: [], total_hosts_found: 0 },
        scanHealth: { engine_status: 'running', coverage_status: 'full' },
      },
    });

    // Decrement user's scan quota
    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: { scansRemaining: { decrement: 1 }, lastScanDate: new Date() },
      });
    }

    // Start async scan
    const scanner = new WebScannerService();
    scanner.run(scan.id, targetUrl, domain, {
      scanProfile: body.options?.scan_profile || 'standard',
      maxPages: body.options?.max_pages || 30,
      maxDepth: body.options?.max_depth || 3,
      respectRobots: body.options?.respect_robots ?? true,
      discoverSubdomains: body.discover_subdomains,
    }).catch(err => {
      console.error(`Scan ${scan.id} failed:`, err);
    });

    return { scan_id: scan.id, status: 'started' };
  });

  // GET /api/web-scan/status/:scanId - Polling endpoint (1.5s interval from frontend)
  app.get('/status/:scanId', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = await prisma.webScan.findUnique({
      where: { id: scanId },
      select: {
        id: true, url: true, domain: true, status: true, progress: true,
        stage: true, pagesScanned: true, requestsMade: true, discovery: true,
        errorMessage: true, findingsCount: true, riskScore: true,
      },
    });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });
    return scan;
  });

  // GET /api/web-scan/result/:scanId - Full results
  app.get('/result/:scanId', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = await prisma.webScan.findUnique({ where: { id: scanId } });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });
    return scan;
  });

  // POST /api/web-scan/analyze-exploitability
  app.post('/analyze-exploitability', async (request) => {
    const { findings } = request.body as { findings: any[] };
    const service = new ExploitabilityService();
    return await service.analyze(findings || []);
  });
  // GET /api/web-scan/history
  app.get('/history', { preHandler: [(app as any).authenticate] }, async (request: any) => {
    const scans = await prisma.webScan.findMany({
      where: { userId: request.user.id, isParentScan: true },
      select: { id: true, domain: true, url: true, status: true, riskScore: true, findingsCount: true, createdAt: true },
      orderBy: { createdAt: 'desc' }, take: 20,
    });
    return { scans };
  });
}

import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../config/database';
import { EmailScannerService } from '../../services/scanning/emailScanner';

const startSchema = z.object({
  domain: z.string().min(3),
});

export async function emailScanRoutes(app: FastifyInstance) {
  // POST /api/email-scan/start
  app.post('/start', { preHandler: [(app as any).optionalAuth] }, async (request, reply) => {
    const body = startSchema.parse(request.body);
    const user = (request as any).user;
    const domain = body.domain.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '').split('/')[0];

    const scan = await prisma.emailScan.create({
      data: {
        userId: user?.id || null,
        domain,
        status: 'RUNNING',
        progress: 0,
        currentStage: 'DNS',
        scoreBreakdown: { spf: 0, dkim: 0, dmarc: 0, relay: 0, misc: 0, ports: 0 },
      },
    });

    // Start async scan
    const scanner = new EmailScannerService();
    scanner.run(scan.id, domain).catch(err => {
      console.error(`Email scan ${scan.id} failed:`, err);
    });

    return { scan_id: scan.id };
  });

  // GET /api/email-scan/status/:scanId (polling every 3s)
  app.get('/status/:scanId', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = await prisma.emailScan.findUnique({
      where: { id: scanId },
      select: {
        id: true, domain: true, status: true, progress: true,
        currentStage: true, emailSecurityScore: true, scoreBreakdown: true,
      },
    });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });
    return scan;
  });

  // GET /api/email-scan/result/:scanId
  app.get('/result/:scanId', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = await prisma.emailScan.findUnique({ where: { id: scanId } });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });
    return scan;
  });
  // GET /api/email-scan/history
  app.get('/history', { preHandler: [(app as any).authenticate] }, async (request: any) => {
    const scans = await prisma.emailScan.findMany({
      where: { userId: request.user.id },
      select: { id: true, domain: true, status: true, emailSecurityScore: true, scoreRating: true, createdAt: true },
      orderBy: { createdAt: 'desc' }, take: 20,
    });
    return { scans };
  });
}

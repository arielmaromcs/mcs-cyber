import { FastifyInstance } from 'fastify';
import { prisma } from '../../config/database';

import { Prisma } from '@prisma/client';

export async function scanDataRoutes(app: FastifyInstance) {
  // POST /api/data/latest-scans — Fetch all scan types for a target
  app.post('/latest-scans', async (request) => {
    const { target, limit = 10 } = request.body as any;
    const domain = target.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '').split('/')[0];

    const [emailScans, webScans, threatScans] = await Promise.all([
      prisma.emailScan.findMany({
        where: { domain },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: { id: true, createdAt: true, emailSecurityScore: true, status: true, domain: true },
      }),
      prisma.webScan.findMany({
        where: { domain },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: { id: true, createdAt: true, webSecurityScore: true, riskScore: true, status: true, domain: true },
      }),
      prisma.webScan.findMany({
        where: { domain, threatIntelData: { not: Prisma.DbNull } },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: { id: true, createdAt: true, threatIntelData: true, status: true, domain: true },
      }),
    ]);

    return {
      email_scans: emailScans.map(s => ({
        id: s.id, created_at: s.createdAt,
        summary: { score: s.emailSecurityScore, status: s.status },
      })),
      web_scans: webScans.map(s => ({
        id: s.id, created_at: s.createdAt,
        summary: { score: s.webSecurityScore, status: s.status },
      })),
      threat_scans: threatScans.map(s => ({
        id: s.id, created_at: s.createdAt,
        summary: { score: 0, status: s.status },
      })),
    };
  });

  // GET /api/data/scan-history/:target
  app.get('/scan-history/:target', async (request) => {
    const { target } = request.params as { target: string };
    return await prisma.scanHistory.findMany({
      where: { target: { contains: target } },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
  });

  // POST /api/data/upgrade — Stripe checkout stub
  app.post('/upgrade', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    // Stub: In production, create Stripe checkout session
    return {
      url: `https://checkout.stripe.com/mock?email=${user.email}`,
      message: 'Stripe integration stub. Set STRIPE_SECRET_KEY in .env for production.',
    };
  });
}

import { FastifyInstance } from 'fastify';
import { prisma } from '../../config/database';

import { Prisma } from '@prisma/client';

export async function scanDataRoutes(app: FastifyInstance) {
  // POST /api/data/latest-scans — Fetch all scan types for a target
  app.post('/latest-scans', async (request) => {
    const { target, limit = 10 } = request.body as any;
    // Domain normalization: strip protocol, www, trailing slash, lowercase
    const domain = (target || '').replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '').split('/')[0].toLowerCase();

    const [emailScans, webScans, threatScans] = await Promise.all([
      prisma.emailScan.findMany({ where: { domain, status: 'COMPLETED' }, orderBy: { createdAt: 'desc' }, take: limit }),
      prisma.webScan.findMany({ where: { domain, status: 'COMPLETED' }, orderBy: { createdAt: 'desc' }, take: limit }),
      prisma.webScan.findMany({
        where: { domain, threatIntelData: { not: Prisma.DbNull }, status: 'COMPLETED' },
        orderBy: { createdAt: 'desc' }, take: limit,
      }),
    ]);

    return {
      email_scans: emailScans.map(s => ({ id: s.id, created_at: s.createdAt, summary: `Email: ${s.emailSecurityScore || 0}`, raw: s })),
      web_scans: webScans.map(s => ({ id: s.id, created_at: s.createdAt, summary: `Web: ${s.webSecurityScore || 0}`, raw: s })),
      threat_scans: threatScans.map(s => ({ id: s.id, created_at: s.createdAt, summary: `Threat: ${s.domain}`, raw: s })),
    };
  });

  // POST /api/data/save-scan-history — Persist attack surface scores for trending
  app.post('/save-scan-history', { preHandler: [(app as any).optionalAuth] }, async (request) => {
    const { target, attack_score, risk_level, email_risk, web_risk, network_risk, total_deductions, deductions_detail } = request.body as any;
    const user = (request as any).user;
    const history = await prisma.scanHistory.create({
      data: {
        target: target || '',
        userEmail: user?.email || 'guest',
        attackScore: Math.round(attack_score || 0),
        riskLevel: risk_level || 'unknown',
        emailRisk: email_risk || 0,
        webRisk: web_risk || 0,
        networkRisk: network_risk || 0,
        totalDeductions: total_deductions || 0,
        deductionsDetail: deductions_detail || [],
      },
    });
    return { id: history.id, success: true };
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
    return { url: `https://checkout.stripe.com/mock?email=${user.email}`, message: 'Stripe integration stub' };
  });
}

import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { MitreCorrelationService } from '../../services/analysis/mitreCorrelation';
import { PdfService } from '../../services/analysis/pdfService';
import { prisma } from '../../config/database';

const correlationSchema = z.object({
  target: z.string().min(1),
  email_scan: z.any().nullable().optional(),
  web_scan: z.any().nullable().optional(),
  threat_intel: z.any().nullable().optional(),
});

const pdfSchema = z.object({
  target: z.string(),
  attackScore: z.number(),
  riskLevel: z.string(),
  topFindings: z.array(z.any()).optional(),
  attackerView: z.any().optional(),
  recommendations: z.array(z.any()).optional(),
});

export async function mitreRoutes(app: FastifyInstance) {
  // POST /api/mitre/correlate — LLM-based MITRE ATT&CK mapping
  app.post('/correlate', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = correlationSchema.parse(request.body);
    const user = (request as any).user;

    if (!body.email_scan && !body.web_scan && !body.threat_intel) {
      return { error: 'At least one scan data source required' };
    }

    const service = new MitreCorrelationService();
    const result = await service.correlate(body.target, body.email_scan, body.web_scan, body.threat_intel);

    // Save to ScanHistory for trending
    if (result.attack_score) {
      await prisma.scanHistory.create({
        data: {
          userId: user?.id,
          target: body.target,
          userEmail: user?.email,
          attackScore: result.attack_score.score || 0,
          riskLevel: result.attack_score.rating?.toLowerCase() || 'low',
          emailRisk: 0,
          webRisk: 0,
          networkRisk: 0,
        },
      });
    }

    return result;
  });

  // POST /api/mitre/executive-pdf — Generate executive summary PDF
  app.post('/executive-pdf', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = pdfSchema.parse(request.body);
    const user = (request as any).user;
    const pdfService = new PdfService();
    const pdfResult = await pdfService.generateExecutivePdf(body);

    await prisma.executiveReport.create({
      data: {
        userId: user?.id,
        target: body.target,
        userEmail: user?.email,
        attackScore: body.attackScore,
        riskLevel: body.riskLevel,
        pdfUrl: pdfResult.pdf_url,
        fileSizeKb: pdfResult.file_size_kb,
      },
    });

    return pdfResult;
  });

  // POST /api/mitre/save-history
  app.post('/save-history', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = request.body as any;
    const user = (request as any).user;
    return await prisma.scanHistory.create({
      data: {
        userId: user?.id,
        target: body.target,
        userEmail: user?.email,
        attackScore: body.attack_score || 0,
        riskLevel: body.risk_level || 'low',
        emailRisk: body.email_risk || 0,
        webRisk: body.web_risk || 0,
        networkRisk: body.network_risk || 0,
        totalDeductions: body.total_deductions || 0,
        deductionsDetail: body.deductions_detail || null,
      },
    });
  });
}

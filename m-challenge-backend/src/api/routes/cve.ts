import { FastifyInstance } from 'fastify';
import { CveService } from '../../services/cve/cveService';

const cveService = new CveService();

export async function cveRoutes(app: FastifyInstance) {
  app.get('/cve', async (req: any, reply) => {
    try {
      const { severity, limit = '50', offset = '0' } = req.query as any;
      const cves = await cveService.getLatest({ severity, limit: parseInt(limit), offset: parseInt(offset) });
      return reply.send(cves);
    } catch (err: any) { return reply.status(500).send({ error: err.message }); }
  });

  app.get('/cve/stats', async (req: any, reply) => {
    try { return reply.send(await cveService.getStats()); }
    catch (err: any) { return reply.status(500).send({ error: err.message }); }
  });

  app.post('/cve/refresh', async (req: any, reply) => {
    try { return reply.send(await cveService.fetchAndStore()); }
    catch (err: any) { return reply.status(500).send({ error: err.message }); }
  });

  app.post('/cve/send-alert', async (req: any, reply) => {
    try { await cveService.sendDailyAlert(); return reply.send({ ok: true }); }
    catch (err: any) { return reply.status(500).send({ error: err.message }); }
  });
}

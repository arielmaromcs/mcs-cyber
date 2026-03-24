import { FastifyInstance } from 'fastify';
import { NucleiService } from '../../services/nuclei/nucleiService';

export async function nucleiRoutes(app: FastifyInstance) {
  const svc = new NucleiService();

  // POST /api/nuclei/scan — התחל סריקה
  app.post('/scan', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    const { target, severity, customerId, description } = request.body as any;
    if (!target) throw new Error('target is required');
    const scanId = await svc.startScan(user.id, target, { severity, customerId, description });
    return { scanId, status: 'RUNNING' };
  });

  // GET /api/nuclei/scans — רשימת סריקות
  app.get('/scans', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    return await svc.listScans(user.id, user.role === 'ADMIN');
  });

  // GET /api/nuclei/scan/:id — סטטוס + תוצאות
  app.get('/scan/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    const scan = await svc.getScan(id);
    if (!scan) throw new Error('Scan not found');
    return scan;
  });

  // DELETE /api/nuclei/scan/:id
  app.delete('/scan/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    const { prisma } = await import('../../config/database');
    await (prisma as any).$executeRaw`DELETE FROM nuclei_scans WHERE id=${id}`;
    return { success: true };
  });
}

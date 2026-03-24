import { FastifyInstance } from 'fastify';
import { prisma } from '../../config/database';

export async function clientRoutes(app: FastifyInstance) {

  app.get('/', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    if (user.role === 'ADMIN') {
      return await (prisma as any).$queryRaw`SELECT * FROM clients ORDER BY created_at DESC`;
    }
    return await (prisma as any).$queryRaw`SELECT * FROM clients WHERE created_by = ${user.id} ORDER BY created_at DESC`;
  });

  app.post('/', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    const { name, domain, ip, office, contactName, contactPhone, contactEmail, serviceAgreement, notes } = request.body as any;
    const id = crypto.randomUUID();
    const now = new Date();
    await (prisma as any).$executeRaw`
      INSERT INTO clients (id, name, domain, ip, office, contact_name, contact_phone, contact_email, service_agreement, notes, created_by, created_at, updated_at)
      VALUES (${id}, ${name}, ${domain||null}, ${ip||null}, ${office||null}, ${contactName||null}, ${contactPhone||null}, ${contactEmail||null}, ${serviceAgreement||false}, ${notes||null}, ${user.id}, ${now}, ${now})
    `;
    return { id, name };
  });

  app.patch('/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    const { name, domain, ip, office, contactName, contactPhone, contactEmail, serviceAgreement, notes } = request.body as any;
    const now = new Date();
    await (prisma as any).$executeRaw`
      UPDATE clients SET name=${name}, domain=${domain||null}, ip=${ip||null}, office=${office||null},
        contact_name=${contactName||null}, contact_phone=${contactPhone||null},
        contact_email=${contactEmail||null}, service_agreement=${serviceAgreement||false},
        notes=${notes||null}, updated_at=${now}
      WHERE id=${id}
    `;
    return { success: true };
  });

  app.delete('/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    await (prisma as any).$executeRaw`DELETE FROM clients WHERE id = ${id}`;
    return { success: true };
  });

  // GET /clients/:id/schedules — כל הסריקות המשויכות ללקוח
  app.get('/:id/schedules', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    const [web, email, threat] = await Promise.all([
      (prisma as any).$queryRaw`SELECT *, 'web' as _type FROM web_scan_schedules WHERE customer_id = ${id} ORDER BY created_at DESC`,
      (prisma as any).$queryRaw`SELECT *, 'email' as _type FROM email_scan_schedules WHERE customer_id = ${id} ORDER BY created_at DESC`,
      (prisma as any).$queryRaw`SELECT *, 'threat' as _type FROM threat_intel_schedules WHERE customer_id = ${id} ORDER BY created_at DESC`,
    ]);
    return [...(web as any[]), ...(email as any[]), ...(threat as any[])];
  });

}
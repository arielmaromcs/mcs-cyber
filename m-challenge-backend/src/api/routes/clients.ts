import { FastifyInstance } from 'fastify';
import { prisma } from '../../config/database';

export async function clientRoutes(app: FastifyInstance) {

  // GET all clients
  app.get('/', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    const where = user.role === 'ADMIN' ? {} : { createdBy: user.id };
    const result = await (prisma as any).$queryRaw`
      SELECT * FROM clients 
      ${user.role === 'ADMIN' ? (prisma as any).$queryRaw`WHERE 1=1` : (prisma as any).$queryRaw`WHERE created_by = ${user.id}`}
      ORDER BY created_at DESC
    `;
    return result;
  });

  // POST create client
  app.post('/', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    const { name, domain, ip, office, contactName, contactPhone, contactEmail, serviceAgreement, notes } = request.body as any;
    const id = crypto.randomUUID();
    await (prisma as any).$executeRaw`
      INSERT INTO clients (id, name, domain, ip, office, contact_name, contact_phone, contact_email, service_agreement, notes, created_by)
      VALUES (${id}, ${name}, ${domain||null}, ${ip||null}, ${office||null}, ${contactName||null}, ${contactPhone||null}, ${contactEmail||null}, ${serviceAgreement||false}, ${notes||null}, ${user.id})
    `;
    return { id, name, domain, ip, office, contactName, contactPhone, contactEmail, serviceAgreement, notes };
  });

  // PATCH update client
  app.patch('/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    const { name, domain, ip, office, contactName, contactPhone, contactEmail, serviceAgreement, notes } = request.body as any;
    await (prisma as any).$executeRaw`
      UPDATE clients SET
        name = ${name}, domain = ${domain||null}, ip = ${ip||null}, office = ${office||null},
        contact_name = ${contactName||null}, contact_phone = ${contactPhone||null},
        contact_email = ${contactEmail||null}, service_agreement = ${serviceAgreement||false},
        notes = ${notes||null}, updated_at = NOW()
      WHERE id = ${id}
    `;
    return { success: true };
  });

  // DELETE client
  app.delete('/:id', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { id } = request.params as any;
    await (prisma as any).$executeRaw`DELETE FROM clients WHERE id = ${id}`;
    return { success: true };
  });
}

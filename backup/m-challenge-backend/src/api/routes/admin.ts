import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { prisma } from '../../config/database';
import { EmailService } from '../../services/email/emailService';

export async function adminRoutes(app: FastifyInstance) {
  // GET /api/admin/users
  app.get('/users', { preHandler: [(app as any).requireAdmin] }, async () => {
    return await prisma.user.findMany({
      select: { id: true, email: true, fullName: true, role: true, plan: true, scansRemaining: true, createdAt: true, lastScanDate: true },
      orderBy: { createdAt: 'desc' },
    });
  });

  // POST /api/admin/users/invite
  app.post('/users/invite', { preHandler: [(app as any).requireAdmin] }, async (request) => {
    const { email, role, scans_remaining } = request.body as any;
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return { error: 'User already exists', user: existing };

    const tempPassword = Math.random().toString(36).slice(-10);
    const passwordHash = await bcrypt.hash(tempPassword, 12);
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        role: role || 'BASIC_SCANS',
        plan: role === 'ADMIN' ? 'ENTERPRISE' : 'FREE',
        scansRemaining: scans_remaining || 20,
      },
    });

    return { success: true, user: { id: user.id, email: user.email, role: user.role }, tempPassword };
  });

  // PATCH /api/admin/users/:userId
  app.patch('/users/:userId', { preHandler: [(app as any).requireAdmin] }, async (request, reply) => {
    const { userId } = request.params as { userId: string };
    const { role, scans_remaining, plan } = request.body as any;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) return reply.status(404).send({ error: 'User not found' });

    const data: any = {};
    if (role) data.role = role;
    if (scans_remaining !== undefined) data.scansRemaining = scans_remaining;
    if (plan) data.plan = plan;

    return await prisma.user.update({ where: { id: userId }, data });
  });

  // DELETE /api/admin/users/:userId
  app.delete('/users/:userId', { preHandler: [(app as any).requireAdmin] }, async (request, reply) => {
    const { userId } = request.params as { userId: string };
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) return reply.status(404).send({ error: 'User not found' });
    if (target.role === 'ADMIN') return reply.status(403).send({ error: 'Cannot delete admin users' });
    await prisma.user.delete({ where: { id: userId } });
    return { success: true };
  });

  // ---- Email Settings ----

  // POST /api/admin/email-settings
  app.post('/email-settings', { preHandler: [(app as any).requireAdmin] }, async (request) => {
    const { action, provider, settings } = request.body as any;

    if (action === 'get') {
      return await prisma.adminEmailSettings.findFirst() || null;
    }

    if (action === 'save') {
      // Header injection prevention
      if (settings) {
        for (const val of Object.values(settings)) {
          if (typeof val === 'string' && /[\r\n]/.test(val)) {
            return { error: 'Invalid characters in settings' };
          }
        }
      }
      const existing = await prisma.adminEmailSettings.findFirst();
      const data = { provider, ...settings };
      if (existing) {
        return await prisma.adminEmailSettings.update({ where: { id: existing.id }, data });
      }
      return await prisma.adminEmailSettings.create({ data });
    }

    if (action === 'verify' || action === 'test') {
      const emailService = new EmailService();
      try {
        await emailService.sendTest(settings?.test_email || (request as any).user?.email, provider, settings);
        return { success: true, message: 'Test email sent' };
      } catch (err: any) {
        return { success: false, message: err.message };
      }
    }

    return { error: 'Invalid action' };
  });

  // GET /api/admin/stats
  app.get('/stats', { preHandler: [(app as any).requireAdmin] }, async () => {
    const [totalUsers, totalWebScans, totalEmailScans] = await Promise.all([
      prisma.user.count(),
      prisma.webScan.count(),
      prisma.emailScan.count(),
    ]);
    const admins = await prisma.user.count({ where: { role: 'ADMIN' } });
    return { totalUsers, admins, regularUsers: totalUsers - admins, totalWebScans, totalEmailScans };
  });
}

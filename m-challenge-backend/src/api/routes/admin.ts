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
    const roleMap: Record<string, string> = { 'admin': 'ADMIN', 'basic_scans': 'BASIC_SCANS', 'full_scans': 'FULL_SCANS', 'Admin': 'ADMIN', 'Basic': 'BASIC_SCANS', 'Full': 'FULL_SCANS' };
    const normalizedRole = roleMap[role] || (role || '').toUpperCase() || 'BASIC_SCANS';
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return { error: 'User already exists', user: existing };

    const tempPassword = Math.random().toString(36).slice(-10);
    const passwordHash = await bcrypt.hash(tempPassword, 12);
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        role: normalizedRole as any,
        plan: normalizedRole === 'ADMIN' ? 'ENTERPRISE' : 'FREE',
        scansRemaining: scans_remaining || 20,
      },
    });


    // Send invitation email
    try {
      const emailSvc = new EmailService();
      const loginUrl = (request.headers.origin as string) || "https://m-challenge.co.il";
      const inviteHtml = "<div style=\"font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;\">"
        + "<div style=\"background: linear-gradient(135deg, #0c1220 0%, #1a1f3a 100%); padding: 30px; border-radius: 12px; color: #fff;\">"
        + "<div style=\"text-align: center; margin-bottom: 20px;\"><span style=\"color:#2d7aff; font-size:16px; font-weight:600;\">M-Challenge Security Scanner</span></div>"
        + "<h2 style=\"color: #fff; margin: 0 0 10px; font-size: 22px; text-align: center;\">You have Been Invited!</h2>"
        + "<p style=\"color: #8899b4; text-align: center; margin-bottom: 25px;\">You have been invited to join M-Challenge Security Scanner.</p>"
        + "<div style=\"background: #111827; border-radius: 10px; padding: 20px; margin-bottom: 20px;\">"
        + "<p style=\"color: #8899b4; margin: 0 0 8px; font-size: 13px;\">Your login credentials:</p>"
        + "<p style=\"color: #fff; margin: 0 0 4px; font-size: 14px;\"><strong>Email:</strong> " + email + "</p>"
        + "<p style=\"color: #fff; margin: 0 0 4px; font-size: 14px;\"><strong>Password:</strong> <span style=\"color: #10b981; font-family: monospace; font-size: 16px;\">" + tempPassword + "</span></p>"
        + "<p style=\"color: #fff; margin: 0; font-size: 14px;\"><strong>Role:</strong> " + normalizedRole + "</p>"
        + "</div>"
        + "<div style=\"text-align: center; margin: 20px 0;\"><a href=\"" + loginUrl + "/login\" style=\"background: #2d7aff; color: #fff; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 600;\">Sign In Now</a></div>"
        + "<p style=\"color: #4a5568; font-size: 11px; text-align: center; margin-top: 20px;\">Please change your password after first login.</p>"
        + "</div></div>";
      await emailSvc.send(email, "[M-Challenge] You have Been Invited - Login Credentials", inviteHtml);
      console.log("[Admin] Invitation email sent to:", email);
    } catch (emailErr: any) {
      console.error("[Admin] Failed to send invitation email:", emailErr.message);
    }
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
      const s = settings || {};
      const data: any = {
        provider,
        smtpHost: s.smtp_host || s.smtpHost || undefined,
        smtpPort: s.smtp_port ? parseInt(s.smtp_port) : s.smtpPort || undefined,
        smtpUser: s.smtp_user || s.smtpUser || undefined,
        smtpPassword: s.smtp_password || s.smtpPassword || undefined,
        msTenantId: s.ms_tenant_id || s.msTenantId || undefined,
        msClientId: s.ms_client_id || s.msClientId || undefined,
        msClientSecret: s.ms_client_secret || s.msClientSecret || undefined,
        fromEmail: s.from_email || s.fromEmail || undefined,
        fromName: s.from_name || s.fromName || undefined,
        replyTo: s.reply_to || s.replyTo || undefined,
      };
      // Remove undefined keys
      Object.keys(data).forEach(k => data[k] === undefined && delete data[k]);
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

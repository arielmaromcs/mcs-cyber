import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../config/database';
import { ScheduleService } from '../../services/scheduling/scheduleService';

const createSchema = z.object({
  type: z.enum(['web', 'email', 'threat']),
  data: z.object({
    target: z.string().min(1),
    frequency: z.enum(['daily', 'weekly', 'monthly']).default('weekly'),
    start_time: z.string().default('09:00'),
    notify_emails: z.array(z.string().email()).max(5).default([]),
  description: z.string().optional(),
    notify_on_complete: z.boolean().default(true),
    notify_on_critical: z.boolean().default(true),
    custom_message: z.string().optional(),
    customer_id: z.string().optional(),
    nmap_config: z.any().optional(),
  }),
});

export async function scheduleRoutes(app: FastifyInstance) {
  const scheduleService = new ScheduleService();

  // POST /api/schedules/create
  app.post('/create', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = createSchema.parse(request.body);
    const user = (request as any).user;
    return await scheduleService.create(user.id, user.email, body.type, body.data);
  });

  // DELETE /api/schedules/:type/:scheduleId
  app.delete('/:type/:scheduleId', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { type, scheduleId } = request.params as { type: string; scheduleId: string };
    return await scheduleService.delete(type as any, scheduleId);
  });

  // PATCH /api/schedules/toggle
  app.patch('/toggle', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { type, schedule_id, current_status } = request.body as any;
    return await scheduleService.toggle(type, schedule_id, current_status);
  });

  // POST /api/schedules/trigger — Force run the scheduler now (admin only)
  app.post('/trigger', { preHandler: [(app as any).authenticate] }, async () => {
    const svc = new ScheduleService();
    const result = await svc.executeScheduledScans();
    return { triggered: true, timestamp: new Date().toISOString() };
  });

  // POST /api/schedules/test
  app.post('/test', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { scan_type, target, nmap_config } = request.body as any;
    return await scheduleService.testScanIndividual(scan_type, target, nmap_config);
  });

  // POST /api/schedules/run-now/:type/:scheduleId
  app.post('/run-now/:type/:scheduleId', { preHandler: [(app as any).authenticate], config: { rawBody: false } }, async (request) => {
    const { type, scheduleId } = request.params as { type: string; scheduleId: string };
    let schedule: any;
    if (type === 'web') schedule = await prisma.webScanSchedule.findUnique({ where: { id: scheduleId } });
    else if (type === 'email') schedule = await prisma.emailScanSchedule.findUnique({ where: { id: scheduleId } });
    else if (type === 'threat') schedule = await prisma.threatIntelSchedule.findUnique({ where: { id: scheduleId } });
    if (!schedule) return { error: 'Schedule not found' };
    (scheduleService as any)._currentScheduleId = scheduleId;
    const target = schedule.url || schedule.domain || schedule.target;
    const result = await scheduleService.testScanIndividual(type as any, target, schedule.nmapConfig, true);
    return result;
  });

  // GET /api/schedules/list
  app.get('/list', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    const [web, email, threat] = await Promise.all([
      prisma.webScanSchedule.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' } }),
      prisma.emailScanSchedule.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' } }),
      prisma.threatIntelSchedule.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' } }),
    ]);
    return { web, email, threat };
  });

  // GET /api/schedules/logs
  app.get('/logs', { preHandler: [(app as any).authenticate] }, async (request) => {
    const user = (request as any).user;
    // Get scheduleIds for this user first, then fetch logs
    const scheduleIds: string[] = [];
    const [ws, es, ts] = await Promise.all([
      prisma.webScanSchedule.findMany({ where: { userId: user.id }, select: { id: true } }),
      prisma.emailScanSchedule.findMany({ where: { userId: user.id }, select: { id: true } }),
      prisma.threatIntelSchedule.findMany({ where: { userId: user.id }, select: { id: true } }),
    ]);
    scheduleIds.push(...ws.map(s => s.id), ...es.map(s => s.id), ...ts.map(s => s.id));

    return await prisma.scheduleExecutionLog.findMany({
      where: { scheduleId: { in: scheduleIds } },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
  });
}

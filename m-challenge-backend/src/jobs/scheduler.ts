import cron from 'node-cron';
import { prisma } from '../config/database';

const activeCrons = new Map<string, cron.ScheduledTask>();

function timeToCron(startTime: string, frequency: string): string {
  const [hour, minute] = (startTime || '09:00').split(':').map(Number);
  const m = minute || 0;
  const h = hour || 9;
  switch (frequency) {
    case 'DAILY': return `${m} ${h} * * *`;
    case 'WEEKLY': return `${m} ${h} * * 1`;
    case 'MONTHLY': return `${m} ${h} 1 * *`;
    default: return `${m} ${h} * * *`;
  }
}

async function runScheduledScan(type: string, scheduleId: string) {
  const { ScheduleService } = await import('../services/scheduling/scheduleService');
  const scheduleService = new ScheduleService();
  try {
    let schedule: any;
    if (type === 'web') {
      schedule = await prisma.webScanSchedule.findUnique({ where: { id: scheduleId } });
      if (!schedule || !schedule.isActive) return;
      (scheduleService as any)._currentScheduleId = scheduleId;
      const result = await scheduleService.testScanIndividual('web', schedule.url, undefined, true);
      await prisma.webScanSchedule.update({ where: { id: scheduleId }, data: { lastScanId: result.scan_id, lastScanDate: new Date() } });
      await prisma.scheduleExecutionLog.create({ data: { scheduleId, scheduleType: 'web', target: schedule.url, status: 'success', scanIds: result.scan_id ? [result.scan_id] : [] } });
      console.log('[Scheduler] Web scan executed:', schedule.url);
    } else if (type === 'email') {
      schedule = await prisma.emailScanSchedule.findUnique({ where: { id: scheduleId } });
      if (!schedule || !schedule.isActive) return;
      (scheduleService as any)._currentScheduleId = scheduleId;
      const result = await scheduleService.testScanIndividual('email', schedule.domain, undefined, true);
      await prisma.emailScanSchedule.update({ where: { id: scheduleId }, data: { lastScanId: result.scan_id, lastScanDate: new Date() } });
      await prisma.scheduleExecutionLog.create({ data: { scheduleId, scheduleType: 'email', target: schedule.domain, status: 'success', scanIds: result.scan_id ? [result.scan_id] : [] } });
      console.log('[Scheduler] Email scan executed:', schedule.domain);
    } else if (type === 'threat') {
      schedule = await prisma.threatIntelSchedule.findUnique({ where: { id: scheduleId } });
      if (!schedule || !schedule.isActive) return;
      (scheduleService as any)._currentScheduleId = scheduleId;
      const result = await scheduleService.testScanIndividual('threat', schedule.target, schedule.nmapConfig as any, true);
      await prisma.threatIntelSchedule.update({ where: { id: scheduleId }, data: { lastScanDate: new Date() } });
      await prisma.scheduleExecutionLog.create({ data: { scheduleId, scheduleType: 'threat', target: schedule.target, status: 'success', scanIds: result.scan_id ? [result.scan_id] : [] } });
      console.log('[Scheduler] Threat scan executed:', schedule.target);
    }
  } catch (err: any) {
    console.error('[Scheduler] Scan failed:', type, scheduleId, err.message);
    await prisma.scheduleExecutionLog.create({ data: { scheduleId, scheduleType: type, target: 'unknown', status: 'failed', errorMessage: err.message } }).catch(() => {});
  }
}

export function registerScheduleCron(type: string, scheduleId: string, startTime: string, frequency: string) {
  const key = `${type}_${scheduleId}`;
  if (activeCrons.has(key)) {
    activeCrons.get(key)!.stop();
    activeCrons.delete(key);
  }
  const cronExpr = timeToCron(startTime, frequency);
  console.log(`[Scheduler] Registering ${type} scan ${scheduleId} at cron: ${cronExpr}`);
  const task = cron.schedule(cronExpr, () => {
    console.log(`[Scheduler] Triggering ${type} scan ${scheduleId} at ${new Date().toISOString()}`);
    runScheduledScan(type, scheduleId);
  }, { timezone: process.env.TZ || 'Asia/Jerusalem' });
  activeCrons.set(key, task);
}

export function unregisterScheduleCron(type: string, scheduleId: string) {
  const key = `${type}_${scheduleId}`;
  if (activeCrons.has(key)) {
    activeCrons.get(key)!.stop();
    activeCrons.delete(key);
    console.log(`[Scheduler] Unregistered ${type} scan ${scheduleId}`);
  }
}

export async function initScheduler() {
  console.log('[Scheduler] Loading all active schedules...');
  const webSchedules = await prisma.webScanSchedule.findMany({ where: { isActive: true } });
  for (const s of webSchedules) registerScheduleCron('web', s.id, s.startTime, s.frequency);
  const emailSchedules = await prisma.emailScanSchedule.findMany({ where: { isActive: true } });
  for (const s of emailSchedules) registerScheduleCron('email', s.id, s.startTime, s.frequency);
  const threatSchedules = await prisma.threatIntelSchedule.findMany({ where: { isActive: true } });
  for (const s of threatSchedules) registerScheduleCron('threat', s.id, s.startTime, s.frequency);
  console.log(`[Scheduler] ${activeCrons.size} cron jobs registered`);

// CVE Daily Feed - every day at 07:00
cron.schedule('0 7 * * *', async () => {
  console.log('[CVE Cron] Starting daily CVE fetch...');
  try {
    const { CveService } = await import('../services/cve/cveService');
    const svc = new CveService();
    await svc.fetchAndStore();
    await svc.sendDailyAlert();
  } catch (err: any) {
    console.error('[CVE Cron] Error:', err.message);
  }
}, { timezone: process.env.TZ || 'Asia/Jerusalem' });

}

/**
 * ScheduleService - CRUD operations + job queue management for recurring scans.
 * 
 * Supports: daily/weekly/monthly web/email/threat scans.
 * Logs each execution in ScheduleExecutionLog.
 * Sends email notifications on completion.
 */

import { prisma } from '../../config/database';
import { registerScheduleCron, unregisterScheduleCron } from '../../jobs/scheduler';
import { WebScannerService } from '../scanning/webScanner';
import { EmailScannerService } from '../scanning/emailScanner';

type ScheduleType = 'web' | 'email' | 'threat';

export class ScheduleService {
  async create(userId: string, userEmail: string, type: ScheduleType, data: any) {
    const freqMap: Record<string, any> = { daily: 'DAILY', weekly: 'WEEKLY', monthly: 'MONTHLY' };
    const freq = freqMap[data.frequency] || 'WEEKLY';

    if (type === 'web') {
      const sched = await prisma.webScanSchedule.create({
        data: {
          userId,
          url: data.target,
          userEmail,
          notifyEmails: data.notify_emails || [],
        description: data.description || null,

          frequency: freq,
          startTime: data.start_time || '09:00',
          notifyOnComplete: data.notify_on_complete ?? true,
          notifyOnCritical: data.notify_on_critical ?? true,
          customMessage: data.custom_message,
          customerId: data.customer_id || null,
          isActive: true,
        },
      });
      registerScheduleCron('web', sched.id, data.start_time || '09:00', freq);
    }

    if (type === 'email') {
      const sched = await prisma.emailScanSchedule.create({
        data: {
          userId,
          domain: data.target,
          userEmail,
          notifyEmails: data.notify_emails || [],
        description: data.description || null,
          frequency: freq,
          startTime: data.start_time || '09:00',
          notifyOnComplete: data.notify_on_complete ?? true,
          notifyOnCritical: data.notify_on_critical ?? true,
          customerId: data.customer_id || null,
          isActive: true,
        },
      });
      registerScheduleCron('email', sched.id, data.start_time || '09:00', freq);
    }

    if (type === 'threat') {
      const sched = await prisma.threatIntelSchedule.create({
        data: {
          userId,
          target: data.target,
          userEmail,
          notifyEmails: data.notify_emails || [],
        description: data.description || null,
          frequency: freq,
          startTime: data.start_time || '09:00',
          notifyOnComplete: data.notify_on_complete ?? true,
          notifyOnCritical: data.notify_on_critical ?? true,
          isActive: true,
          nmapConfig: data.nmap_config || null,
          customerId: data.customer_id || null,
        },
      });
      registerScheduleCron('threat', sched.id, data.start_time || '09:00', freq);
    }

    return { error: 'Invalid schedule type' };
  }

  async delete(type: ScheduleType, scheduleId: string) {
    if (type === 'web') { await prisma.webScanSchedule.delete({ where: { id: scheduleId } }); unregisterScheduleCron('web', scheduleId); }
    else if (type === 'email') { await prisma.emailScanSchedule.delete({ where: { id: scheduleId } }); unregisterScheduleCron('email', scheduleId); }
    else if (type === 'threat') { await prisma.threatIntelSchedule.delete({ where: { id: scheduleId } }); unregisterScheduleCron('threat', scheduleId); }
    return { success: true };
  }

  async toggle(type: string, scheduleId: string, currentStatus: boolean) {
    const newStatus = !currentStatus;
    if (type === 'web') await prisma.webScanSchedule.update({ where: { id: scheduleId }, data: { isActive: newStatus } });
    else if (type === 'email') { await prisma.emailScanSchedule.update({ where: { id: scheduleId }, data: { isActive: newStatus } }); if (!newStatus) unregisterScheduleCron('email', scheduleId); }
    else if (type === 'threat') { await prisma.threatIntelSchedule.update({ where: { id: scheduleId }, data: { isActive: newStatus } }); if (!newStatus) unregisterScheduleCron('threat', scheduleId); }
    return { success: true, is_active: newStatus };
  }

  async testScanIndividual(scanType: string, target: string, nmapConfig?: any, fromSchedule = false) {
    if (scanType === 'web') {
      const scan = await prisma.webScan.create({
        data: {
          url: target, domain: target.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0],
          status: 'RUNNING', progress: 0, stage: 'INIT', scanProfile: 'quick',
          findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [],
        },
      });
      const scanner = new WebScannerService();
      scanner.run(scan.id, target, scan.domain, {
        scanProfile: 'quick', maxPages: 10, maxDepth: 2,
        respectRobots: true, discoverSubdomains: false,
      }, fromSchedule).catch(err => console.error(`Test scan failed: ${err.message}`));
      return { scan_id: scan.id, status: 'started' };
    }

    if (scanType === 'email') {
      const domain = target.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
      const scan = await prisma.emailScan.create({
        data: { domain, status: 'RUNNING', progress: 0, currentStage: 'DNS',
          scoreBreakdown: { spf: 0, dkim: 0, dmarc: 0, relay: 0, misc: 0, ports: 0 } },
      });
      const scanner = new EmailScannerService();
      (scanner as any)._fromSchedule = fromSchedule;
      (scanner as any)._scheduleId = (this as any)._currentScheduleId;
      scanner.run(scan.id, domain).catch(err => console.error(`Test email scan failed: ${err.message}`));
      return { scan_id: scan.id, status: 'started' };
    }

    if (scanType === 'threat') {
      const { NmapService } = await import('../nmap/nmapService');
      const nmap = new NmapService();
      (nmap as any)._fromSchedule = fromSchedule;
      (nmap as any)._scheduleId = (this as any)._currentScheduleId;
      const result = await nmap.startThreatIntelNmap(target, { ...(nmapConfig || {}), scan_a_records: true, scan_mx_records: true, client_approved: true, profile: (nmapConfig as any)?.profile || 'baseline_syn_1000' });
      const jobId = result.jobs?.[0]?.scan_id || result.jobs?.[0]?.job_id || null;
      return { scan_id: jobId, status: jobId ? 'started' : 'no_targets', jobs: result.jobs, discovery: result.discovery?.steps };
    }

    return { error: 'Unsupported scan type for test' };
  }

  /**
   * Execute all active schedules that are due. Called by cron job.
   */
  async executeScheduledScans() {
    const now = new Date();
    const hour = now.getHours().toString().padStart(2, '0');
    const minute = now.getMinutes() < 30 ? '00' : '30'; // 30-min windows

    // Web schedules
    const webSchedules = await prisma.webScanSchedule.findMany({
      where: { isActive: true },
    });
    for (const schedule of webSchedules) {
      if (!this.isDue(schedule.frequency, schedule.lastScanDate, schedule.startTime, now)) continue;
      try {
        (this as any)._currentScheduleId = schedule.id;
        const result = await this.testScanIndividual('web', schedule.url);
        await prisma.webScanSchedule.update({
          where: { id: schedule.id },
          data: { lastScanId: result.scan_id, lastScanDate: now },
        });
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'web', target: schedule.url,
            status: 'success', scanIds: result.scan_id ? [result.scan_id] : [],
          },
        });
      } catch (err: any) {
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'web', target: schedule.url,
            status: 'failed', errorMessage: err.message,
          },
        });
      }
    }

    // Email schedules
    const emailSchedules = await prisma.emailScanSchedule.findMany({
      where: { isActive: true },
    });
    for (const schedule of emailSchedules) {
      if (!this.isDue(schedule.frequency, schedule.lastScanDate, schedule.startTime, now)) continue;
      try {
        (this as any)._currentScheduleId = schedule.id;
        const result = await this.testScanIndividual('email', schedule.domain);
        await prisma.emailScanSchedule.update({
          where: { id: schedule.id },
          data: { lastScanId: result.scan_id, lastScanDate: now },
        });
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'email', target: schedule.domain,
            status: 'success', scanIds: result.scan_id ? [result.scan_id] : [],
          },
        });
      } catch (err: any) {
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'email', target: schedule.domain,
            status: 'failed', errorMessage: err.message,
          },
        });
      }
    }

    // Threat Intel schedules
    const threatSchedules = await prisma.threatIntelSchedule.findMany({ where: { isActive: true } });
    for (const schedule of threatSchedules) {
      if (!this.isDue(schedule.frequency, schedule.lastScanDate, schedule.startTime, now)) continue;
      try {
        (this as any)._currentScheduleId = schedule.id;
        const result = await this.testScanIndividual('threat', schedule.target, schedule.nmapConfig as any);
        await prisma.threatIntelSchedule.update({
          where: { id: schedule.id },
          data: { lastScanDate: now },
        });
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'threat', target: schedule.target,
            status: 'success', scanIds: result.scan_id ? [result.scan_id] : [],
          },
        });
      } catch (err: any) {
        await prisma.scheduleExecutionLog.create({
          data: {
            scheduleId: schedule.id, scheduleType: 'threat', target: schedule.target,
            status: 'failed', errorMessage: err.message,
          },
        });
      }
    }

  }
  private isDue(frequency: string, lastScan: Date | null, startTime: string, now: Date): boolean {
    if (!lastScan) return true; // Never ran

    const elapsed = now.getTime() - lastScan.getTime();
    const hour = parseInt(startTime.split(':')[0] || '9');
    const currentHour = now.getHours();

    // Only run near the scheduled hour (±1 hour window)
    if (Math.abs(currentHour - hour) > 1) return false;

    switch (frequency) {
      case 'DAILY': return elapsed > 23 * 60 * 60 * 1000;
      case 'WEEKLY': return elapsed > 6 * 24 * 60 * 60 * 1000;
      case 'MONTHLY': return elapsed > 27 * 24 * 60 * 60 * 1000;
      default: return elapsed > 6 * 24 * 60 * 60 * 1000;
    }
  }
}

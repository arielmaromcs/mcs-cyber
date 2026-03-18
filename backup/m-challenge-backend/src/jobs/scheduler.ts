/**
 * Cron job runner for scheduled scans.
 * Runs every 30 minutes and checks for due schedules.
 * 
 * Alternative: Use BullMQ for more robust job scheduling.
 * This built-in cron approach works well for moderate scale.
 */

import cron from 'node-cron';
import { ScheduleService } from '../services/scheduling/scheduleService';

let started = false;

export function startScheduler() {
  if (started) return;
  started = true;

  const scheduleService = new ScheduleService();

  // Run every 30 minutes
  cron.schedule('*/30 * * * *', async () => {
    console.log(`[Scheduler] Running scheduled scan check at ${new Date().toISOString()}`);
    try {
      await scheduleService.executeScheduledScans();
    } catch (err: any) {
      console.error('[Scheduler] Error executing scheduled scans:', err.message);
    }
  });

  console.log('[Scheduler] Cron scheduler started (every 30 minutes)');
}

import { execFile } from 'child_process';
import { promisify } from 'util';
import { prisma } from '../../config/database';

const execFileAsync = promisify(execFile);

export class NucleiService {

  async startScan(userId: string, target: string, options: {
    severity?: string;
    customerId?: string;
    description?: string;
  } = {}): Promise<string> {
    const scanId = crypto.randomUUID();
    const now = new Date();
    await (prisma as any).$executeRaw`
      INSERT INTO nuclei_scans (id, user_id, target, status, severity, customer_id, description, started_at, created_at, updated_at)
      VALUES (${scanId}, ${userId}, ${target}, 'RUNNING', ${options.severity || 'critical,high,medium,low'},
              ${options.customerId || null}, ${options.description || null}, ${now}, ${now}, ${now})
    `;
    this.runScan(scanId, target, options.severity || 'critical,high,medium,low').catch(console.error);
    return scanId;
  }

  private async runScan(scanId: string, target: string, severity: string): Promise<void> {
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      const cmd = `/usr/local/bin/nuclei -u "${target}" -severity ${severity} -jsonl -silent -timeout 10 -rate-limit 50 -bulk-size 25 -concurrency 10 -no-interactsh`;
      const { stdout } = await execAsync(cmd, { timeout: 300000, maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: '/usr/bin:/usr/local/bin:/bin' } });

      const findings = this.parseOutput(stdout);
      const summary = this.buildSummary(findings);
      const now = new Date();
      await (prisma as any).$executeRaw`
        UPDATE nuclei_scans
        SET status='COMPLETED', findings=${JSON.stringify(findings)}::jsonb,
            summary=${JSON.stringify(summary)}::jsonb, completed_at=${now}, updated_at=${now}
        WHERE id=${scanId}
      `;
    } catch (err: any) {
      const now = new Date();
      await (prisma as any).$executeRaw`
        UPDATE nuclei_scans SET status='FAILED', error_message=${err.message}, updated_at=${now}
        WHERE id=${scanId}
      `;
    }
  }

  private parseOutput(stdout: string): any[] {
    const findings: any[] = [];
    for (const line of stdout.split('\n').filter(l => l.trim())) {
      try {
        const item = JSON.parse(line);
        findings.push({
          template: item['template-id'] || '',
          name: item.info?.name || item['template-id'] || '',
          severity: item.info?.severity || 'info',
          host: item.host || '',
          matched: item['matched-at'] || '',
          description: item.info?.description || '',
          tags: item.info?.tags || [],
          cvss: item.info?.classification?.['cvss-score'] || null,
          cve: item.info?.classification?.['cve-id']?.[0] || null,
        });
      } catch {}
    }
    return findings;
  }

  private buildSummary(findings: any[]): any {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.severity?.toLowerCase() || 'info';
      counts[sev] = (counts[sev] || 0) + 1;
    }
    const score = Math.max(0, 100 - (counts.critical * 25) - (counts.high * 15) - (counts.medium * 8) - (counts.low * 3));
    return { total: findings.length, counts, score };
  }

  async getScan(scanId: string): Promise<any> {
    const rows = await (prisma as any).$queryRaw`SELECT * FROM nuclei_scans WHERE id=${scanId}`;
    return (rows as any[])[0] || null;
  }

  async listScans(userId: string, isAdmin: boolean): Promise<any[]> {
    if (isAdmin) {
      return await (prisma as any).$queryRaw`SELECT * FROM nuclei_scans ORDER BY created_at DESC LIMIT 100`;
    }
    return await (prisma as any).$queryRaw`SELECT * FROM nuclei_scans WHERE user_id=${userId} ORDER BY created_at DESC LIMIT 100`;
  }
}

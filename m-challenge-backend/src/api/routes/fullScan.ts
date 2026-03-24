import { FastifyInstance } from 'fastify';
import { prisma } from '../../config/database';
import { EmailScannerService } from '../../services/scanning/emailScanner';
import { NmapService } from '../../services/nmap/nmapService';
import { EmailService } from '../../services/email/emailService';

export async function fullScanRoutes(app: FastifyInstance) {

  app.post('/start', { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const user = (request as any).user;
    const { target, notifyEmails, frequency, startTime } = request.body as any;
    if (!target) return reply.status(400).send({ error: 'Target required' });

    const domain = target.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

    // Create schedule in DB
    const sched = await prisma.threatIntelSchedule.create({
      data: {
        userId: user.id,
        target: domain,
        userEmail: user.email,
        notifyEmails: notifyEmails || [user.email],
        description: `Full Scan - ${domain}`,
        frequency: ({ daily: 'DAILY', weekly: 'WEEKLY', monthly: 'MONTHLY' } as any)[frequency] || 'WEEKLY',
        startTime: startTime || '09:00',
        isActive: true,
        nmapConfig: { scan_a_records: true, scan_mx_records: true, scan_txt_records: true, profile: 'security_posture', include_cve_nse: true, full_scan: true },
      },
    });

    return { id: sched.id, status: 'created', domain };
  });

  app.post('/run-now', { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const user = (request as any).user;
    const { target, notifyEmails } = request.body as any;
    if (!target) return reply.status(400).send({ error: 'Target required' });

    const domain = target.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    const emails = notifyEmails || [user.email];

    // Run async
    runFullScan(domain, emails, user.id).catch(err => console.error('[FullScan] Error:', err.message));

    return { status: 'started', domain, message: 'Full scan started - results will be emailed' };
  });
}

async function runFullScan(domain: string, notifyEmails: string[], userId: string) {
  console.log('[FullScan] Starting full scan for:', domain);
  const results: any = { domain, startedAt: new Date().toISOString(), email: null, ports: null, tls: null };

  // 1. Email scan
  try {
    const emailScan = await prisma.emailScan.create({
      data: { domain, status: 'RUNNING', progress: 0, currentStage: 'DNS', scoreBreakdown: { spf: 0, dkim: 0, dmarc: 0, relay: 0, misc: 0, ports: 0 } },
    });
    const emailScanner = new EmailScannerService();
    await emailScanner.run(emailScan.id, domain);
    // Wait for scan to complete (poll DB)
    let emailResult: any = null;
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 3000));
      emailResult = await prisma.emailScan.findUnique({ where: { id: emailScan.id } });
      if (emailResult?.status === 'COMPLETED' || emailResult?.status === 'FAILED') break;
    }
    results.email = emailResult;
    console.log('[FullScan] Email scan done, score:', (emailResult as any)?.email_security_score);
  } catch (e: any) { console.error('[FullScan] Email scan failed:', e.message); }

  // 2. Port scan - wait for completion
  try {
    const nmap = new NmapService();
    const nmapResult = await nmap.startThreatIntelNmap(domain, {
      scan_a_records: true, scan_mx_records: true, scan_txt_records: false,
      profile: 'baseline_syn_1000', include_cve_nse: false, client_approved: true,
    });
    const jobs = nmapResult?.jobs || [];
    const allPorts: any[] = [];
    // Poll until all jobs complete
    for (const job of jobs) {
      if (!job.job_id) continue;
      let attempts = 0;
      while (attempts < 60) {
        await new Promise(r => setTimeout(r, 3000));
        const status = await nmap.nmapStatus(job.job_id);
        if (status.status === 'completed' || status.status === 'failed') {
          if (status.open_ports) allPorts.push(...status.open_ports);
          break;
        }
        attempts++;
      }
    }
    results.ports = { jobs, allPorts, discovery: nmapResult?.discovery };
    console.log('[FullScan] Port scan done, open ports:', allPorts.length);
  } catch (e: any) { console.error('[FullScan] Port scan failed:', e.message); }

  // 3. TLS scan
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    const { stdout } = await execAsync(`sslscan --no-colour ${domain}:443`, { timeout: 30000, shell: '/bin/sh' });
    results.tls = { raw: stdout, scannedAt: new Date().toISOString() };
    console.log('[FullScan] TLS scan done');
  } catch (e: any) { console.error('[FullScan] TLS scan failed:', e.message); }

  // Send email report
  await sendFullScanReport(domain, results, notifyEmails);
}

async function sendFullScanReport(domain: string, results: any, notifyEmails: string[]) {
  try {
    const emailService = new EmailService();

    const emailScore = (results.email as any)?.totalScore || 0;
    const emailStatus = emailScore >= 80 ? '✅' : emailScore >= 50 ? '⚠️' : '❌';

    const tlsOk = results.tls?.raw?.includes('TLSv1.3') ? '✅' : '⚠️';

    const openPorts = results.ports?.jobs?.length || 0;

    const html = `
<div style="font-family:monospace; background:#0f172a; color:#e2e8f0; padding:24px; border-radius:12px; max-width:700px;">
  <div style="border-bottom:1px solid #1e3a5f; padding-bottom:16px; margin-bottom:20px;">
    <h1 style="color:#38bdf8; font-size:20px; margin:0">🛡 Full Security Scan Report</h1>
    <div style="color:#64748b; font-size:12px; margin-top:4px">${domain} · ${new Date().toLocaleString('he-IL')}</div>
  </div>

  <table style="width:100%; border-collapse:collapse; margin-bottom:20px;">
    <tr style="background:#1e293b">
      <td style="padding:10px; border:1px solid #1e3a5f; color:#94a3b8; font-size:11px;">SCAN TYPE</td>
      <td style="padding:10px; border:1px solid #1e3a5f; color:#94a3b8; font-size:11px;">STATUS</td>
      <td style="padding:10px; border:1px solid #1e3a5f; color:#94a3b8; font-size:11px;">RESULT</td>
    </tr>
    <tr>
      <td style="padding:10px; border:1px solid #1e3a5f;">📧 Email Security</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${results.email ? '✅ Done' : '❌ Failed'}</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${emailStatus} Score: ${emailScore}/100</td>
    </tr>
    <tr style="background:#0f172a">
      <td style="padding:10px; border:1px solid #1e3a5f;">🔍 Port Scan</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${results.ports ? '✅ Done' : '❌ Failed'}</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${results.ports ? `${openPorts} targets scanned` : 'N/A'}</td>
    </tr>
    <tr>
      <td style="padding:10px; border:1px solid #1e3a5f;">🔒 TLS/SSL</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${results.tls ? '✅ Done' : '❌ Failed'}</td>
      <td style="padding:10px; border:1px solid #1e3a5f;">${results.tls ? tlsOk + ' Scanned' : 'N/A'}</td>
    </tr>
  </table>

  ${results.email ? `
  <div style="background:#1e293b; border-radius:8px; padding:16px; margin-bottom:16px;">
    <h3 style="color:#38bdf8; font-size:13px; margin:0 0 10px">📧 Email Security Details</h3>
    <div style="font-size:11px; color:#94a3b8;">
      SPF: ${(results.email as any)?.spfRecord?.status || 'N/A'} |
      DKIM: ${(results.email as any)?.dkimResults?.length > 0 ? 'Found' : 'Not found'} |
      DMARC: ${(results.email as any)?.dmarcRecord?.status || 'N/A'}
    </div>
  </div>` : ''}

  <div style="color:#475569; font-size:10px; text-align:center; margin-top:20px;">
    Generated by M-Challenge Security Scanner · ${new Date().toISOString()}
  </div>
</div>`;


    const subject = `[M-Challenge] Full Security Scan Report - ${domain}`;
    await emailService.send(notifyEmails, subject, html);
  } catch (e: any) { console.error('[FullScan] Email send failed:', e.message); }
}

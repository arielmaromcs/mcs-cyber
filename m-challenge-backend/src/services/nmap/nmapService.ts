/**
 * NmapService — Runs NMAP locally via child_process (no external API).
 *
 * Ported from the Python nmap-proxy. Supports all profiles:
 *   basic, version, vuln/full, smart_vuln, smart_vuln_heavy,
 *   baseline_syn_1000, service_discovery, security_posture
 *
 * 4-stage threat-intel pipeline:
 *   1. Discovery  — DNS resolution → IPs
 *   2. Scan       — Run nmap locally (async jobs)
 *   3. Decision   — Parse open ports, wait for client approval
 *   4. Exposure   — Deep CVE/NSE scanning on approved ports
 */

import { execFile } from 'child_process';
import { parseStringPromise } from 'xml2js';
import { EmailService } from '../email/emailService';
import { dnsResolve } from '../../utils/scanUtils';

// ─── In-memory job store ───
const JOBS = new Map<string, Job>();

interface Job {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  target: string;
  profile: string;
  created: number;
  updated: number;
  stdout: string;
  stderr: string;
  open_ports: any[];
  services: any[];
  result: any;
  error: string | null;
}

// ─── Helpers ───

function genId(): string {
  return 'nmap_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
}

const TARGET_RE = /^[a-zA-Z0-9.\-:]+$/;
const PORTS_RE = /^[0-9,\-]+$/;

function truncate(s: string, max = 200000): string {
  if (!s || s.length <= max) return s || '';
  return s.slice(0, max) + `\n\n...[truncated ${s.length - max} chars]...`;
}

/**
 * Execute nmap binary. Returns stdout, stderr, return code, elapsed.
 */
function runNmap(args: string[], timeout = 600000): Promise<{ rc: number; stdout: string; stderr: string; elapsed: number }> {
  const t0 = Date.now();
  return new Promise((resolve) => {
    execFile('/usr/bin/nmap', args, { timeout, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      const elapsed = (Date.now() - t0) / 1000;
      resolve({
        rc: err ? (err as any).code || 1 : 0,
        stdout: stdout || '',
        stderr: stderr || '',
        elapsed,
      });
    });
  });
}

// ─── Profile → nmap command builder (matches Python proxy exactly) ───

function buildCmd(target: string, ports: string | null, profile: string): string[] {
  if (!TARGET_RE.test(target)) throw new Error('Invalid target');

  const cmd = ['-Pn', '-n'];

  // Ports
  if (ports) {
    if (!PORTS_RE.test(ports)) throw new Error('Invalid ports');
    cmd.push('-p', ports);
  } else if (!['baseline_syn_1000', 'service_discovery', 'security_posture'].includes(profile)) {
    cmd.push('--top-ports', '100');
  }

  switch (profile) {
    case 'basic':
      cmd.push('-sT');
      break;

    case 'version':
      cmd.push('-sT', '-sV');
      break;

    case 'vuln':
    case 'full':
      cmd.push('-sT', '-sV', '--script', 'vuln,version,safe', '--script-timeout', '8s');
      break;

    case 'baseline_syn_1000':
      if (ports) { cmd.push('-sS'); }
      else { cmd.push('--top-ports', '1000', '-sS'); }
      cmd.push('-T4');
      break;

    case 'service_discovery':
      if (ports) { cmd.push('-sS', '-sV'); }
      else { cmd.push('--top-ports', '2000', '-sS', '-sV'); }
      cmd.push('-T4');
      break;

    case 'security_posture':
      if (ports) { cmd.push('-sS', '-sV'); }
      else { cmd.push('--top-ports', '2000', '-sS', '-sV'); }
      cmd.push('-T4', '--script', 'ssl-cert,ssl-enum-ciphers,http-security-headers');
      break;

    default:
      throw new Error(`Invalid profile: ${profile}`);
  }

  cmd.push(target);
  return cmd;
}

// ─── Parsers ───

/** Parse open ports from nmap text stdout */
function parseOpenPortsText(stdout: string): any[] {
  const ports: any[] = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+?))?\s*$/);
    if (m) {
      const rest = (m[4] || '').trim();
      const parts = rest.split(/\s+/);
      ports.push({
        port: parseInt(m[1]),
        protocol: m[2],
        state: 'open',
        service: m[3],
        product: parts[0] || '',
        version: parts.slice(1).join(' ') || '',
      });
    }
  }
  return ports;
}

/** Parse open ports + services from nmap XML (-oX -) output */
async function parseOpenPortsXml(xmlText: string): Promise<{ open_ports: string[]; services: any[] }> {
  const open_ports: string[] = [];
  const services: any[] = [];

  try {
    const result = await parseStringPromise(xmlText, { explicitArray: false });
    const hosts = Array.isArray(result?.nmaprun?.host) ? result.nmaprun.host : [result?.nmaprun?.host].filter(Boolean);

    for (const host of hosts) {
      if (host?.status?.$?.state !== 'up') continue;
      const portsEl = host?.ports?.port;
      if (!portsEl) continue;
      const portList = Array.isArray(portsEl) ? portsEl : [portsEl];

      for (const p of portList) {
        const proto = p?.$?.protocol || '';
        const portid = p?.$?.portid || '';
        const state = p?.state?.$?.state || '';
        if (proto !== 'tcp' || !portid || state !== 'open') continue;

        const svc = p?.service?.$ || {};
        let svcName = svc.name || 'unknown';
        const product = svc.product || '';
        const version = svc.version || '';
        const tunnel = svc.tunnel || '';

        if (svcName === 'http' && tunnel === 'ssl') svcName = 'https';

        if (!open_ports.includes(portid)) open_ports.push(portid);
        services.push({ port: portid, service: svcName, product, version, tunnel });
      }
    }
  } catch {
    // Fallback: parse as text
    const textPorts = parseOpenPortsText(xmlText);
    for (const p of textPorts) {
      const id = String(p.port);
      if (!open_ports.includes(id)) open_ports.push(id);
      services.push({ port: id, service: p.service, product: p.product, version: p.version, tunnel: '' });
    }
  }

  return { open_ports, services };
}

/** Parse CVEs and VULNERABLE blocks from NSE stdout */
function parseVulnsFromOutput(stdout: string, ip: string): any[] {
  const vulns: any[] = [];
  const seen = new Set<string>();

  // CVE pattern
  const cveRe = /(CVE-\d{4}-\d+)/g;
  let m;
  while ((m = cveRe.exec(stdout)) !== null) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      vulns.push({ cve: m[1], ip, severity: 'high', description: 'Found in NSE output', source: 'nmap-nse' });
    }
  }

  // VULNERABLE blocks
  const vulnRe = /\|\s+(\S+):\s*\n\|.*?State:\s*VULNERABLE/g;
  while ((m = vulnRe.exec(stdout)) !== null) {
    const title = m[1];
    if (!seen.has(title)) {
      seen.add(title);
      vulns.push({ cve: title, ip, severity: 'critical', description: 'NSE vuln script detected', source: 'nmap-nse' });
    }
  }

  return vulns;
}

// ─── Profile normalization (matches Python) ───

function normalizeProfile(p: string): string {
  const aliases: Record<string, string> = {
    advanced: 'full', full: 'full', vuln: 'vuln', version: 'version', basic: 'basic',
    smart: 'smart_vuln', smart_vuln: 'smart_vuln', smart_heavy: 'smart_vuln_heavy', smart_vuln_heavy: 'smart_vuln_heavy',
    baseline_syn_1000: 'baseline_syn_1000', syn_1000: 'baseline_syn_1000',
    service_discovery: 'service_discovery', discovery: 'service_discovery',
    security_posture: 'security_posture', posture: 'security_posture',
  };
  return aliases[(p || '').trim().toLowerCase()] || 'baseline_syn_1000';
}

// ═══════════════════════════════════════════
//  NmapService — main class
// ═══════════════════════════════════════════

export class NmapService {

  // ─── Stage 1+2: Discovery + Start scans ───

  async startThreatIntelNmap(target: string, nmapConfig: any) {
    const ips: string[] = [];
    const discoverySteps: any[] = [];
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipRegex.test(target)) { ips.push(target); discoverySteps.push({ type: "Direct IP", records_found: 1 }); }

    // A / AAAA records
    if (nmapConfig.scan_a_records !== false) {
      const aRecs = await dnsResolve(target, 'A');
      const a6Recs = await dnsResolve(target, 'AAAA');
      for (const r of aRecs) { if (!ips.includes(r.data)) ips.push(r.data); }
      discoverySteps.push({ type: 'A/AAAA', records_found: aRecs.length + a6Recs.length });
    }

    // MX records → resolve to IPs
    if (nmapConfig.scan_mx_records !== false && !ipRegex.test(target)) {
      const mxRecs = await dnsResolve(target, 'MX');
      for (const mx of mxRecs) {
        const mxHost = mx.data.split(' ').pop()?.replace(/\.$/, '');
        if (mxHost) {
          const mxIps = await dnsResolve(mxHost, 'A');
          for (const r of mxIps) { if (!ips.includes(r.data)) ips.push(r.data); }
        }
      }
      discoverySteps.push({ type: 'MX', records_found: mxRecs.length });
    }

    // SPF ip4 extraction
    const txtRecs = await dnsResolve(target, 'TXT');
    const spfRec = txtRecs.map(r => r.data).find(t => t.includes('v=spf1'));
    if (spfRec) {
      const ip4s = [...spfRec.matchAll(/ip4:(\d+\.\d+\.\d+\.\d+)/g)].map(m => m[1]);
      for (const ip of ip4s) { if (!ips.includes(ip)) ips.push(ip); }
    }

    // Stage 2: start scan per IP
    const profile = normalizeProfile(nmapConfig.profile || 'baseline_syn_1000');
    const jobsList: any[] = [];

    for (const ip of ips.slice(0, 10)) {
      const result = await this.nmapStart({
        target: ip,
        profile,
        client_approved: nmapConfig.client_approved || false,
      });
      jobsList.push({ ip, ...result });
    }

    return {
      discovery: {
        target,
        ips_discovered: ips.length,
        ips,
        steps: discoverySteps,
        a_records: (nmapConfig.scan_a_records !== false) ? (await dnsResolve(target, 'A')).map(r => r.data) : [],
        aaaa_records: (nmapConfig.scan_a_records !== false) ? (await dnsResolve(target, 'AAAA')).map(r => r.data) : [],
        mx_records: (nmapConfig.scan_mx_records !== false) ? (await dnsResolve(target, 'MX')).map(r => r.data) : [],
        txt_records: txtRecs.map(r => r.data),
        ns_records: (await dnsResolve(target, 'NS')).map(r => r.data),
      },
      jobs: jobsList,
      stage: 'scanning',
    };
  }

  // ─── Start a scan (async job or sync) ───

  async nmapStart(params: {
    target: string; profile: string; ports?: string;
    client_approved?: boolean; sync?: boolean;
    max_output?: number;
  }) {
    const { target, ports, client_approved, sync } = params;
    const profile = normalizeProfile(params.profile);

    if (!TARGET_RE.test(target)) return { ok: false, error: 'Invalid target', status: 'failed' };

    // Deep scans need approval
    if (['service_discovery', 'security_posture', 'full', 'vuln', 'smart_vuln', 'smart_vuln_heavy'].includes(profile) && !client_approved) {
      return { ok: false, error: 'client_approved required for this profile', status: 'failed' };
    }

    const maxOutput = params.max_output || 200000;

    // ── Smart 2-stage mode ──
    if (profile === 'smart_vuln' || profile === 'smart_vuln_heavy') {
      return await this._smartVulnScan(target, ports || null, profile, maxOutput);
    }

    // ── Single-stage ──
    const args = buildCmd(target, ports || null, profile);

    if (sync) {
      const { rc, stdout, stderr, elapsed } = await runNmap(args);
      const open_ports = parseOpenPortsText(stdout);
      return {
        ok: true, status: 'completed', profile,
        command: `nmap ${args.join(' ')}`,
        returncode: rc,
        stdout: truncate(stdout, maxOutput),
        stderr: truncate(stderr, maxOutput),
        open_ports,
        timing: { scan_sec: Math.round(elapsed * 100) / 100 },
      };
    }

    // Async: create job, run in background
    const jobId = genId();
    const job: Job = {
      id: jobId, status: 'queued', target, profile,
      created: Date.now(), updated: Date.now(),
      stdout: '', stderr: '', open_ports: [], services: [],
      result: null, error: null,
    };
    JOBS.set(jobId, job);

    setImmediate(async () => {
      job.status = 'running';
      job.updated = Date.now();

      const { rc, stdout, stderr, elapsed } = await runNmap(args);
      job.stdout = stdout;
      job.stderr = stderr;
      job.open_ports = parseOpenPortsText(stdout);
      job.status = rc === 0 || job.open_ports.length > 0 ? 'completed' : 'failed';
      job.error = rc !== 0 && job.open_ports.length === 0 ? `nmap exit code ${rc}` : null;
      job.result = {
        ok: job.status === 'completed', profile,
        command: `nmap ${args.join(' ')}`,
        returncode: rc,
        stdout: truncate(stdout, maxOutput),
        stderr: truncate(stderr, maxOutput),
        open_ports: job.open_ports,
        timing: { scan_sec: Math.round(elapsed * 100) / 100 },
      };
      job.updated = Date.now();

      // Send email notification only if triggered by scheduler
      if ((this as any)._fromSchedule) {
      if (job.status === "completed") {
        try {
          const { prisma } = await import("../../config/database");
          const schedId = (this as any)._scheduleId;
          const scheds = schedId 
            ? await prisma.threatIntelSchedule.findMany({ where: { id: schedId } })
            : await prisma.threatIntelSchedule.findMany({ where: { isActive: true, notifyOnComplete: true } });
          for (const sched of scheds) {
            if (sched.notifyEmails && sched.notifyEmails.length > 0) {
              const emailSvc = new EmailService();
              const ports = job.open_ports || [];
              const portLines = ports.map((p: any) => (typeof p === "object" ? p.port + "/" + p.protocol + " (" + (p.service || "unknown") + ")" : String(p)));
              const portsHtml = portLines.length > 0 ? portLines.map((p: string) => "<tr><td style=\"padding:4px 12px;border-bottom:1px solid #1a2640;color:#e2e8f0;font-size:13px;\">" + p + "</td></tr>").join("") : "<tr><td style=\"padding:8px 12px;color:#10b981;\">No open ports</td></tr>";
              const html = "<div style=\"font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;\"><div style=\"background:linear-gradient(135deg,#0c1220,#1a1f3a);padding:30px;border-radius:12px;color:#fff;\">"
                + "<div style=\"text-align:center;margin-bottom:15px;\"><span style=\"color:#2d7aff;font-size:16px;font-weight:600;\">M-Challenge Security Scanner</span></div>"
                + "<h2 style=\"color:#fff;margin:0 0 5px;font-size:20px;text-align:center;\">Port Exposure Scan Complete</h2>"
                + "<p style=\"color:#8899b4;text-align:center;margin-bottom:20px;\">Target: <strong style=\"color:#fff;\">" + job.target + "</strong></p>"
                + "<div style=\"background:#111827;border-radius:10px;padding:15px;margin-bottom:15px;text-align:center;\">"
                + "<div style=\"font-size:36px;font-weight:700;color:" + (ports.length > 5 ? "#ef4444" : ports.length > 0 ? "#f59e0b" : "#10b981") + ";\">" + ports.length + "</div>"
                + "<div style=\"color:#8899b4;font-size:12px;\">Open Ports Found</div></div>"
                + "<table style=\"width:100%;background:#111827;border-radius:10px;margin-bottom:15px;\"><tr><th style=\"padding:8px 12px;text-align:left;color:#3b82f6;font-size:11px;border-bottom:1px solid #1a2640;\">PORT / SERVICE</th></tr>" + portsHtml + "</table>"
                + "</div></div>";
              const displayName = sched.description ? sched.description + " — " + job.target : job.target;
              await emailSvc.send(sched.notifyEmails.filter(Boolean), "[M-Challenge] Port Scan: " + displayName + " (" + ports.length + " open)", html);
              console.log("[NmapService] Notification sent to:", sched.notifyEmails);
            }
          }
        } catch (ne: any) { console.error("[NmapService] Notif error:", ne.message); }
      }
      }
    });

    return { ok: true, job_id: jobId, status: 'queued' };
  }

  // ─── Poll job status ───

  async nmapStatus(jobId: string) {
    const job = JOBS.get(jobId);
    if (!job) return { status: 'not_found', error: 'Job not found' };

    return {
      status: job.status,
      progress: job.status === 'completed' ? 100 : job.status === 'running' ? 50 : job.status === 'failed' ? 100 : 0,
      open_ports: job.open_ports,
      services: job.services,
      stdout: job.stdout,
      stderr: job.stderr,
      result: job.result,
      error: job.error,
      timing: {
        created: job.created,
        updated: job.updated,
        elapsed_sec: Math.round((job.updated - job.created) / 100) / 10,
      },
    };
  }

  // ─── Port scan (step 1 = discovery, step 2 = version on specific ports) ───

  async nmapPortScan(params: { target: string; step: number; ports?: string; domain?: string; scanId?: string }) {
    if (params.step === 1) {
      return await this.nmapStart({ target: params.target, profile: 'baseline_syn_1000', client_approved: true, sync: true });
    }
    return await this.nmapStart({ target: params.target, profile: 'service_discovery', ports: params.ports, client_approved: true, sync: true });
  }

  // ─── Stage 4: Deep CVE/NSE scanning ───

  async runNmapExposure(params: { scan_id?: string; nmap_config: any; job_results: any[] }) {
    if (!params.nmap_config.client_approved) {
      return { error: 'Client approval required', vulnerabilities: [] };
    }

    const allVulns: any[] = [];

    for (const jobResult of params.job_results) {
      const portList = (jobResult.open_ports || []).map((p: any) => String(p.port || p)).join(',');
      if (!portList) continue;

      // Run vuln scripts on specific ports
      const args = [
        '-Pn', '-n', '-sT',
        '-sV', '--version-intensity', '4',
        '--script', 'vuln,version,safe',
        '--script-timeout', '8s',
        '--max-retries', '1',
        '--host-timeout', '120s',
        '-T4',
        '-p', portList,
        jobResult.ip,
      ];

      const { rc, stdout, stderr, elapsed } = await runNmap(args);
      const vulns = parseVulnsFromOutput(stdout, jobResult.ip);
      const ports = parseOpenPortsText(stdout);

      // Add port details even without vulns
      for (const p of ports) {
        allVulns.push({
          ip: jobResult.ip,
          port: p.port,
          service: p.service,
          product: p.product,
          version: p.version,
          cve: null,
          severity: 'info',
          description: `${p.service} ${p.product} ${p.version}`.trim(),
          source: 'nmap-version',
        });
      }

      allVulns.push(...vulns);
    }

    return { vulnerabilities: allVulns, total_found: allVulns.length };
  }

  // ─── Smart 2-stage: version XML → targeted NSE (matches Python) ───

  private async _smartVulnScan(target: string, ports: string | null, profile: string, maxOutput: number) {
    const t0 = Date.now();

    // Stage 1: Version scan with XML output
    const args1 = [
      '-Pn', '-n', '-sT',
      '-sV', '--version-intensity', '4',
      '--max-retries', '1',
      '--host-timeout', '20s',
      '-T4',
      '-oX', '-',
    ];
    if (ports && PORTS_RE.test(ports)) { args1.push('-p', ports); }
    args1.push(target);

    const s1 = await runNmap(args1);
    const { open_ports, services } = await parseOpenPortsXml(s1.stdout);

    // Stage 2: Targeted NSE on discovered ports
    const scriptExpr = 'vuln,version,safe';
    const args2 = [
      '-Pn', '-n', '-sT',
      '-sV', '--version-intensity', '4',
      '--script', scriptExpr,
      '--script-timeout', '8s',
      '--max-retries', '1',
      '--host-timeout', '120s',
      '-T4',
    ];
    if (open_ports.length) { args2.push('-p', open_ports.join(',')); }
    args2.push(target);

    const s2 = await runNmap(args2);
    const elapsed = (Date.now() - t0) / 1000;

    return {
      ok: true, status: 'completed', profile, mode: 'smart_2stage',
      timing: {
        total_sec: Math.round(elapsed * 100) / 100,
        stage1_sec: Math.round(s1.elapsed * 100) / 100,
        stage2_sec: Math.round(s2.elapsed * 100) / 100,
      },
      stage1: {
        command: `nmap ${args1.join(' ')}`,
        returncode: s1.rc,
        open_ports,
        services,
      },
      stage2: {
        command: `nmap ${args2.join(' ')}`,
        returncode: s2.rc,
        script: scriptExpr,
        stdout: truncate(s2.stdout, maxOutput),
        stderr: truncate(s2.stderr, maxOutput),
      },
      open_ports: open_ports.map(p => {
        const svc = services.find(s => s.port === p);
        return { port: parseInt(p), protocol: 'tcp', state: 'open', service: svc?.service || '', product: svc?.product || '', version: svc?.version || '' };
      }),
      vulnerabilities: parseVulnsFromOutput(s2.stdout, target),
    };
  }
}

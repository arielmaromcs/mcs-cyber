import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NmapService } from '../../services/nmap/nmapService';

const startNmapSchema = z.object({
  target: z.string().min(1),
  nmap_config: z.object({
    scan_a_records: z.boolean().default(true),
    scan_mx_records: z.boolean().default(true),
    profile: z.enum(['baseline_syn_1000', 'service_discovery', 'security_posture']).default('baseline_syn_1000'),
    scan_all_discovered_ports: z.boolean().default(false),
    client_approved: z.boolean().default(false),
  }).optional(),
});

const nmapStartSchema = z.object({
  target: z.string(),
  profile: z.enum(['version', 'smart_vuln', 'baseline_syn_1000', 'service_discovery', 'security_posture', 'vuln', 'full', 'basic']),
  ports: z.string().optional(),
  client_approved: z.boolean().default(false),
  sync: z.boolean().default(false),
});

const exposureSchema = z.object({
  scan_id: z.string().optional(),
  nmap_config: z.object({
    scan_all_discovered_ports: z.boolean(),
    client_approved: z.boolean(),
  }),
  job_results: z.array(z.object({
    ip: z.string(),
    open_ports: z.array(z.object({ port: z.number(), service: z.string() })),
  })),
});

export async function threatIntelRoutes(app: FastifyInstance) {
  const nmap = new NmapService();

  // POST /api/threat-intel/start-nmap — Discovery → Scan orchestration
  app.post('/start-nmap', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = startNmapSchema.parse(request.body);
    return await nmap.startThreatIntelNmap(body.target, body.nmap_config || {
      scan_a_records: true, scan_mx_records: true,
      profile: 'baseline_syn_1000', scan_all_discovered_ports: false, client_approved: false,
    });
  });

  // POST /api/threat-intel/nmap-start — Proxy to NMAP scanning service
  app.post('/nmap-start', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = nmapStartSchema.parse(request.body);
    return await nmap.nmapStart(body);
  });

  // GET /api/threat-intel/nmap-status/:jobId
  app.get('/nmap-status/:jobId', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { jobId } = request.params as { jobId: string };
    return await nmap.nmapStatus(jobId);
  });

  // POST /api/threat-intel/nmap-port-scan — Parse NMAP results (step 1 or 2)
  app.post('/nmap-port-scan', { preHandler: [(app as any).authenticate] }, async (request) => {
    const { target, step, ports, domain, scanId } = request.body as any;
    return await nmap.nmapPortScan({ target, step: step || 1, ports, domain, scanId });
  });

  // POST /api/threat-intel/run-nmap-exposure — Deep CVE scanning
  app.post('/run-nmap-exposure', { preHandler: [(app as any).authenticate] }, async (request) => {
    const body = exposureSchema.parse(request.body);
    return await nmap.runNmapExposure(body);
  });
  // GET /api/client-ip
  app.get('/client-ip', async (request: any, reply: any) => {
    const h = request.headers;
    const cfIp = h['cf-connecting-ip'];
    const xff = h['x-forwarded-for'];
    const xReal = h['x-real-ip'];
    let ip = 'Unknown';
    if (cfIp) ip = Array.isArray(cfIp) ? cfIp[0] : cfIp;
    else if (xff) ip = (Array.isArray(xff) ? xff[0] : xff).split(',')[0].trim();
    else if (xReal) ip = Array.isArray(xReal) ? xReal[0] : xReal;
    else ip = request.ip || 'Unknown';
    return { client_ip: ip };
  });

}


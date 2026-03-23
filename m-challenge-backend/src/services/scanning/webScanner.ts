/**
 * WebScannerService - Complete 10-stage web security scanner.
 * 
 * Stages: DISCOVERY → INIT → TLS → DNS → HEADERS → COOKIES → EXPOSURE → CRAWL → CONTENT → FINALIZE
 * 
 * Implements:
 * - Passive subdomain discovery (crt.sh)
 * - Active subdomain probing (30 common subs via dns.google)
 * - DNS analysis (DNSSEC, CAA, NS, SPF, DMARC, DKIM, takeover risk)
 * - HTTP header security checks
 * - Cookie security analysis
 * - Deep exposure discovery (sitemap, robots, JS mining, extension testing)
 * - Crawl spider
 * - 100+ security rules engine
 * - Weighted budget scoring with worst-case caps
 */

import { EmailService } from '../email/emailService';
import { prisma } from '../../config/database';
import { dnsResolve, safeFetch, safeGet, sleep, parallelBatch, countBySeverity, calculateWebScore, calculateRiskScore } from '../../utils/scanUtils';

interface ScanOptions {
  scanProfile: string;
  maxPages: number;
  maxDepth: number;
  respectRobots: boolean;
  discoverSubdomains: boolean;
}

interface Finding {
  id: string;
  title: string;
  category: string;
  severity: string;
  description: string;
  evidence?: any;
  impact?: string;
  recommendation?: string;
  owasp_category?: string;
  affected_urls?: string[];
  references?: string[];
}

// Stage weights (sum = ~100)
const STAGE_WEIGHTS = { DISCOVERY: 18, INIT: 4, TLS: 12, DNS: 14, HEADERS: 10, COOKIES: 8, EXPOSURE: 10, CRAWL: 14, CONTENT: 5, FINALIZE: 5 };

// 30 common subdomains for safe-active discovery
const COMMON_SUBS = ['www','api','admin','dashboard','cdn','mail','smtp','pop','imap','ftp','dev','staging','test','beta','app','portal','auth','login','sso','docs','blog','shop','store','status','monitor','grafana','jenkins','git','gitlab','kibana'];

export class WebScannerService {
  private allFindings: Finding[] = [];
  private pagesScanned = 0;
  private requestsMade = 0;
  private startTime = 0;

  /**
   * Run the full scan asynchronously. Updates DB progress at each stage.
   */
  async run(scanId: string, url: string, domain: string, options: ScanOptions, fromSchedule = false): Promise<void> {
    this.startTime = Date.now();
    this.allFindings = [];
    this.pagesScanned = 0;
    this.requestsMade = 0;

    try {
      let cumulProgress = 0;

      // ---- STAGE 0: DISCOVERY ----
      if (options.discoverSubdomains) {
        await this.updateProgress(scanId, 2, 'DISCOVERY');
        const discovery = await this.runDiscovery(domain);
        cumulProgress += STAGE_WEIGHTS.DISCOVERY;
        await prisma.webScan.update({ where: { id: scanId }, data: { discovery: discovery as any, progress: cumulProgress, stage: 'INIT' } });
      } else {
        cumulProgress += STAGE_WEIGHTS.DISCOVERY;
        await this.updateProgress(scanId, cumulProgress, 'INIT');
      }

      // ---- STAGE 1-2: INIT + TLS ----
      const isHttps = await this.checkTLS(url, domain);
      cumulProgress += STAGE_WEIGHTS.INIT + STAGE_WEIGHTS.TLS;
      await this.updateProgress(scanId, cumulProgress, 'DNS');

      // ---- STAGE 3: DNS ----
      const dnsAnalysis = await this.analyzeDNS(domain);
      cumulProgress += STAGE_WEIGHTS.DNS;
      await prisma.webScan.update({ where: { id: scanId }, data: { dnsAnalysis: dnsAnalysis as any, progress: cumulProgress, stage: 'HEADERS' } });

      // ---- STAGE 4: HEADERS ----
      const { headers, body } = await this.analyzeHeaders(url, domain);
      cumulProgress += STAGE_WEIGHTS.HEADERS;
      await this.updateProgress(scanId, cumulProgress, 'COOKIES');

      // ---- STAGE 5: COOKIES ----
      this.analyzeCookies(headers, url, isHttps);
      cumulProgress += STAGE_WEIGHTS.COOKIES;
      await this.updateProgress(scanId, cumulProgress, 'EXPOSURE');

      // ---- STAGE 6: EXPOSURE DISCOVERY ----
      const technologies = this.detectTechnologies(headers, body);
      const { exposures, metrics: discoveryMetrics, robotsAnalysis } = await this.deepExposureDiscovery(domain, url, body, technologies);
      cumulProgress += STAGE_WEIGHTS.EXPOSURE;
      await prisma.webScan.update({ where: { id: scanId }, data: {
        exposureFindings: exposures as any, exposuresFound: exposures.length,
        discoveryMetrics: discoveryMetrics as any, robotsAnalysis: robotsAnalysis as any,
        progress: cumulProgress, stage: 'CRAWL',
      }});

      // ---- STAGE 7: CRAWL ----
      const crawlData = await this.crawl(url, domain, options.maxPages, options.maxDepth);
      cumulProgress += STAGE_WEIGHTS.CRAWL;
      await this.updateProgress(scanId, cumulProgress, 'CONTENT');

      // ---- STAGE 8: CONTENT ANALYSIS ----
      // Additional security rules from crawl + headers
      this.runAdditionalSecurityRules(headers, body, isHttps, url);
      cumulProgress += STAGE_WEIGHTS.CONTENT;
      await this.updateProgress(scanId, cumulProgress, 'FINALIZE');

      // ---- STAGE 9: FINALIZE (Scoring with exposure penalties + coverage penalty) ----
      const counts = countBySeverity(this.allFindings);
      const exposureCounts = countBySeverity(exposures.filter((e: any) => e.accessible));
      const coverage = { requestsMade: this.requestsMade, pagesScanned: this.pagesScanned, totalFindings: this.allFindings.length };
      const { score: webScore, cap, capReason, penalties } = calculateWebScore(counts, exposureCounts, coverage);

      const dnsScore = dnsAnalysis.dns_score || 70;
      const riskScore = calculateRiskScore(webScore, dnsScore, 0);
      const duration = Math.round((Date.now() - this.startTime) / 1000);

      await prisma.webScan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          progress: 100,
          stage: 'COMPLETE',
          findings: this.allFindings as any,
          findingsCount: counts as any,
          webSecurityScore: webScore,
          dnsSecurityScore: dnsScore,
          emailSecurityScore: 0,
          riskScore,
          pagesScanned: this.pagesScanned,
          requestsMade: this.requestsMade,
          scanDurationSeconds: duration,
          technologies: technologies as any,
          attackSurface: crawlData.attackSurface as any,
          blockageEvents: (discoveryMetrics.waf_indicators?.waf_detected ? [{ stage: 'EXPOSURE', block_reason: 'WAF detected', classified_cause: 'WAF', count: discoveryMetrics.waf_indicators.count_403 }] : []) as any,
          scanHealth: {
            engine_status: 'completed',
            coverage_status: this.pagesScanned > 5 ? 'full' : this.pagesScanned > 0 ? 'partial' : 'minimal',
            blockage_summary: { total_blocked: discoveryMetrics.waf_indicators?.count_403 || 0 },
          } as any,
          scoreBreakdown: {
            main_domain_score: webScore,
            raw_score_before_cap: 100 - Object.values(penalties).reduce((a, b) => a + b, 0),
            score_cap: cap,
            score_cap_reason: capReason,
            critical_findings: counts.critical,
            high_findings: counts.high,
            penalty_breakdown: penalties,
            findings_by_severity: counts,
            unintended_exposure_risk: { critical: exposureCounts.critical, high: exposureCounts.high, medium: exposureCounts.medium, total_accessible: exposures.filter((e: any) => e.accessible).length },
            data_sufficiency: { pages_scanned: this.pagesScanned, requests_made: this.requestsMade, paths_tested: discoveryMetrics.total_paths_tested },
          } as any,
        },
      });
      // Send email notification only if triggered by scheduler
      if (fromSchedule) {
      try {
        const schedId = (this as any)._scheduleId;
        const schedules = schedId
          ? await prisma.webScanSchedule.findMany({ where: { id: schedId } })
          : await prisma.webScanSchedule.findMany({ where: { isActive: true, notifyOnComplete: true } });
        for (const sched of schedules) {
          const schedDomain = (sched.url || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
          if (sched.notifyEmails && sched.notifyEmails.length > 0) {
            const emailSvc = new EmailService();
            const topFindings = this.allFindings.slice(0, 15).map((f: any) => ({ severity: f.severity, title: f.title, description: (f.description || '').slice(0, 120) }));
            const recs = this.allFindings.filter((f: any) => f.severity === 'critical' || f.severity === 'high').slice(0, 5).map((f: any) => 'Fix: ' + f.title);
            await emailSvc.sendScanNotification(
              sched.notifyEmails.filter(Boolean),
              domain, 'Web Security', riskScore, undefined,
              { findings: topFindings, recommendations: recs, rating: riskScore >= 80 ? 'Good' : riskScore >= 50 ? 'Fair' : 'Needs Improvement', description: sched.description || undefined }
            );
            console.log('[WebScanner] Notification sent to:', sched.notifyEmails);
          }
        }
      } catch (notifErr: any) { console.error('[WebScanner] Notification error:', notifErr.message); }
      } // end fromSchedule check
    } catch (err: any) {
      console.error('[WebScanner] SCAN FAILED:', scanId, err.message, err.stack?.split('\n')[1]);
      await prisma.webScan.update({
        where: { id: scanId },
        data: { status: 'FAILED', errorMessage: err.message || 'Unknown error', stage: 'FAILED' },
      });
      throw err;
    }
  }

  // ======== STAGE IMPLEMENTATIONS ========

  private async updateProgress(scanId: string, progress: number, stage: string) {
    await prisma.webScan.update({
      where: { id: scanId },
      data: { progress: Math.min(99, progress), stage, pagesScanned: this.pagesScanned, requestsMade: this.requestsMade },
    });
  }

  /**
   * DISCOVERY: Passive (crt.sh) + Active (common subs) + Path discovery.
   */
  private async runDiscovery(domain: string) {
    const hostsDiscovered: any[] = [{ host: domain, source: 'primary', resolved: true, reachable: true, scan_status: 'completed' }];
    const pathsDiscovered: any[] = [];

    // Passive: crt.sh TLS SAN
    try {
      const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(10000) });
      if (res.ok) {
        const certs = await res.json();
        const names = new Set<string>();
        for (const cert of (certs as any[]).slice(0, 200)) {
          (cert.name_value || '').split('\n').forEach((n: string) => {
            const clean = n.trim().replace('*.', '');
            if (clean.endsWith(domain) && clean !== domain && !clean.includes('*')) names.add(clean);
          });
        }
        for (const name of [...names].slice(0, 50)) {
          hostsDiscovered.push({ host: name, source: 'tls-san', resolved: false, reachable: false, scan_status: 'idle' });
        }
      }
      this.requestsMade++;
    } catch { /* crt.sh timeout is fine */ }

    // Active: Probe common subdomains via DNS (parallel batches of 10)
    const subsToCheck = COMMON_SUBS.map(sub => `${sub}.${domain}`).filter(h => !hostsDiscovered.find(x => x.host === h));
    const dnsResults = await parallelBatch(subsToCheck, 10, async (host) => {
      const records = await dnsResolve(host, 'A');
      this.requestsMade++;
      return { host, found: records.length > 0 };
    });
    for (const r of dnsResults) {
      if (r?.found) hostsDiscovered.push({ host: r.host, source: 'safe-active', resolved: true, reachable: true, scan_status: 'idle' });
    }

    return {
      hosts_discovered: hostsDiscovered,
      paths_discovered: pathsDiscovered,
      total_hosts_found: hostsDiscovered.length,
      total_hosts_scanned: 1,
      total_paths_found: pathsDiscovered.length,
    };
  }

  /**
   * TLS: Check HTTPS availability.
   */
  private async checkTLS(url: string, domain: string): Promise<boolean> {
    const httpsUrl = url.startsWith('https') ? url : `https://${domain}`;
    const res = await safeFetch(httpsUrl, { timeout: 10000 });
    this.requestsMade++;

    const isHttps = res !== null && res.url.startsWith('https');
    if (!isHttps) {
      this.addFinding({ id: 'tls-no-https', title: 'HTTPS Not Available', category: 'tls', severity: 'critical',
        description: 'Site does not support HTTPS. All traffic is transmitted in cleartext.',
        impact: 'Complete lack of encryption — credentials, sessions, data all exposed',
        recommendation: 'Enable HTTPS with a valid TLS certificate (e.g., Let\'s Encrypt)',
        evidence: { url: httpsUrl, method: 'HEAD', status: res?.status || 0, timestamp: new Date().toISOString() } });
    }
    return isHttps;
  }

  /**
   * DNS: Full DNS analysis (DNSSEC, CAA, NS, SPF, DMARC, DKIM, takeover).
   */
  private async analyzeDNS(domain: string): Promise<any> {
    const records: any = {};
    let configScore = 100, emailDnsScore = 100, takeoverScore = 100, hygieneScore = 100;

    // Fetch all record types (parallel)
    const DNS_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'CNAME', 'SRV'];
    const dnsResults = await Promise.all(DNS_TYPES.map(async (type) => {
      const recs = await dnsResolve(domain, type);
      this.requestsMade++;
      return { type, data: recs.map(r => r.data) };
    }));
    for (const r of dnsResults) records[r.type.toLowerCase()] = r.data;

    // DNSSEC + DMARC in parallel
    const [dnskeyRecords, dmarcRecords] = await Promise.all([
      dnsResolve(domain, 'DNSKEY'),
      dnsResolve(`_dmarc.${domain}`, 'TXT'),
    ]);
    this.requestsMade += 2;
    const dnssecEnabled = dnskeyRecords.length > 0;
    if (!dnssecEnabled) {
      configScore -= 20;
      this.addFinding({ id: 'dns-no-dnssec', title: 'DNSSEC Not Enabled', category: 'dns', severity: 'medium',
        description: 'DNSSEC is not configured for this domain.', impact: 'DNS responses can be spoofed via cache poisoning',
        recommendation: 'Enable DNSSEC at your DNS registrar' });
    }

    // CAA
    if ((records.caa || []).length === 0) configScore -= 15;

    // NS redundancy
    if ((records.ns || []).length < 2) configScore -= 10;

    // SPF
    const txtRecords: string[] = records.txt || [];
    const spfRecord = txtRecords.find((t: string) => t.includes('v=spf1'));
    if (!spfRecord) {
      emailDnsScore -= 40;
    } else if (spfRecord.includes('+all')) {
      emailDnsScore -= 30;
    } else if (spfRecord.includes('~all')) {
      emailDnsScore -= 10;
    }

    // DMARC (already fetched in parallel above)
    const dmarcRecord = dmarcRecords.map(r => r.data).find(d => d.includes('v=DMARC1'));
    if (!dmarcRecord) {
      emailDnsScore -= 30;
    } else if (dmarcRecord.includes('p=none')) {
      emailDnsScore -= 20;
    }

    // DKIM heuristic (parallel)
    let dkimFound = false;
    const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'dkim', 'k1'];
    const dkimResults = await Promise.all(DKIM_SELECTORS.map(async (sel) => {
      const recs = await dnsResolve(`${sel}._domainkey.${domain}`, 'TXT');
      this.requestsMade++;
      return recs.length > 0;
    }));
    dkimFound = dkimResults.some(Boolean);
    if (!dkimFound) emailDnsScore -= 10;

    // Takeover risk (dangling CNAMEs)
    const cnames: string[] = records.cname || [];
    const riskyTargets = ['github.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'pantheon.io', 'ghost.io'];
    for (const cn of cnames) {
      if (riskyTargets.some(rt => cn.includes(rt))) {
        takeoverScore -= 25;
        this.addFinding({ id: `dns-takeover-${cn}`, title: 'DNS Takeover Risk', category: 'dns', severity: 'high',
          description: `CNAME points to potentially claimable service: ${cn}`,
          impact: 'Attacker could claim the subdomain and serve malicious content',
          recommendation: 'Remove dangling CNAME records or claim the external service' });
      }
    }

    const dnsScore = Math.max(0, Math.min(100, Math.round(
      configScore * 0.30 + emailDnsScore * 0.35 + takeoverScore * 0.25 + hygieneScore * 0.10
    )));

    return {
      dns_score: dnsScore,
      config_score: Math.max(0, configScore),
      email_dns_score: Math.max(0, emailDnsScore),
      takeover_risk_score: takeoverScore,
      hygiene_score: hygieneScore,
      records,
      dnssec: { enabled: dnssecEnabled },
      email_security: { spf: !!spfRecord, dmarc: !!dmarcRecord, dkim: dkimFound },
    };
  }

  /**
   * HEADERS: Fetch main page and check security headers.
   */
  private async analyzeHeaders(url: string, domain: string): Promise<{ headers: Record<string, string>; body: string }> {
    const targetUrl = url.startsWith('http') ? url : `https://${domain}`;
    const res = await safeGet(targetUrl, 15000);
    this.requestsMade++;

    const headers = res?.headers || {};
    const body = res?.body || '';

    // Security header checks
    const headerChecks = [
      { header: 'strict-transport-security', id: 'hsts-missing', title: 'HSTS Header Missing', severity: 'high', desc: 'HTTP Strict Transport Security is not configured.' },
      { header: 'content-security-policy', id: 'csp-missing', title: 'Content Security Policy Missing', severity: 'high', desc: 'No CSP header. XSS attacks are not mitigated at browser level.' },
      { header: 'x-frame-options', id: 'xfo-missing', title: 'X-Frame-Options Missing', severity: 'medium', desc: 'Page can be embedded in iframes from any origin.' },
      { header: 'x-content-type-options', id: 'xcto-missing', title: 'X-Content-Type-Options Missing', severity: 'low', desc: 'MIME-type sniffing prevention not configured.' },
      { header: 'referrer-policy', id: 'ref-missing', title: 'Referrer-Policy Missing', severity: 'low', desc: 'Browser may leak full URL in Referer header.' },
      { header: 'permissions-policy', id: 'pp-missing', title: 'Permissions-Policy Missing', severity: 'low', desc: 'Browser features not explicitly restricted.' },
    ];

    for (const check of headerChecks) {
      if (!headers[check.header]) {
        this.addFinding({
          id: check.id, title: check.title, category: 'headers', severity: check.severity,
          description: check.desc,
          impact: `Missing ${check.header} header reduces browser security protections`,
          recommendation: `Add the ${check.header} header`,
          evidence: { url: targetUrl, method: 'GET', status: res?.status || 0, timestamp: new Date().toISOString() },
          owasp_category: 'A05:2021 Security Misconfiguration',
        });
      }
    }

    // Server disclosure
    if (headers['server'] && /\d/.test(headers['server'])) {
      this.addFinding({ id: 'server-disclosure', title: 'Server Version Disclosed', category: 'disclosure', severity: 'low',
        description: `Server header reveals: ${headers['server']}`, evidence: { url: targetUrl, value: headers['server'] } });
    }

    // X-Powered-By
    if (headers['x-powered-by']) {
      this.addFinding({ id: 'powered-by', title: 'X-Powered-By Disclosed', category: 'disclosure', severity: 'low',
        description: `X-Powered-By: ${headers['x-powered-by']}`, evidence: { url: targetUrl, value: headers['x-powered-by'] } });
    }

    // CORS wildcard
    if (headers['access-control-allow-origin'] === '*') {
      this.addFinding({ id: 'cors-wildcard', title: 'CORS Wildcard Origin', category: 'cors', severity: 'medium',
        description: 'Access-Control-Allow-Origin is set to * — any site can make requests.', evidence: { url: targetUrl } });
    }

    return { headers, body };
  }

  /**
   * COOKIES: Check Secure, HttpOnly, SameSite flags.
   */
  private analyzeCookies(headers: Record<string, string>, url: string, isHttps: boolean) {
    const setCookie = headers['set-cookie'];
    if (!setCookie) return;

    const cookies = setCookie.split(/,(?=[^;]*=)/); // Split on comma not inside attributes
    for (const cookie of cookies) {
      const lower = cookie.toLowerCase();
      const name = cookie.split('=')[0]?.trim();

      if (isHttps && !lower.includes('secure')) {
        this.addFinding({ id: `cookie-no-secure-${name}`, title: 'Cookie Without Secure Flag', category: 'cookies', severity: 'medium',
          description: `Cookie "${name}" lacks the Secure flag on HTTPS site.`, evidence: { url, cookie: name } });
      }
      if (!lower.includes('httponly') && /session|sid|token|auth/i.test(name || '')) {
        this.addFinding({ id: `cookie-no-httponly-${name}`, title: 'Session Cookie Without HttpOnly', category: 'cookies', severity: 'medium',
          description: `Cookie "${name}" appears to be a session cookie without HttpOnly flag.`, evidence: { url, cookie: name } });
      }
      if (!lower.includes('samesite')) {
        this.addFinding({ id: `cookie-no-samesite-${name}`, title: 'Cookie Without SameSite', category: 'cookies', severity: 'medium',
          description: `Cookie "${name}" lacks the SameSite attribute.`, evidence: { url, cookie: name } });
      }
    }
  }

  /**
   * EXPOSURE: Deep exposure discovery — full implementation.
   * 
   * 1. Parse sitemap.xml (extract <loc> tags)
   * 2. Parse robots.txt (extract Disallow: paths, flag sensitive ones)
   * 3. Deep JS Mining (extract routes, api paths, keywords from bundles)
   * 4. Derivative inference (from discovered paths → test siblings)
   * 5. Framework-specific paths (Spring, Laravel, Django, WordPress — only if detected)
   * 6. Extension-based file discovery per directory (.env, .bak, .sql, .map, config.*)
   * 7. Test all via HEAD with WAF tracking
   */
  private async deepExposureDiscovery(domain: string, baseUrl: string, htmlBody: string, technologies?: any): Promise<{ exposures: any[]; metrics: any; robotsAnalysis: any }> {
    const exposures: any[] = [];
    const targetBase = baseUrl.startsWith('http') ? baseUrl.replace(/\/$/, '') : `https://${domain}`;
    const discoveredDirs = new Set<string>(['/']);
    const discoveredPaths = new Set<string>();
    const sources: Record<string, number> = { static: 0, sitemap: 0, robots: 0, js_analysis: 0, extension: 0, framework: 0, crawl: 0 };
    let wafCount = 0;
    let totalTested = 0;
    let robotsAnalysis: any = { accessible: false };

    // === 1. Sitemap.xml parsing ===
    try {
      const sitemapRes = await safeGet(`${targetBase}/sitemap.xml`, 8000);
      this.requestsMade++;
      if (sitemapRes?.ok && sitemapRes.body.includes('<loc>')) {
        const locs = [...sitemapRes.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]).slice(0, 100);
        for (const loc of locs) {
          try {
            const u = new URL(loc);
            discoveredPaths.add(u.pathname);
            const dir = u.pathname.split('/').slice(0, -1).join('/') || '/';
            discoveredDirs.add(dir);
            sources.sitemap++;
          } catch { /* skip */ }
        }
        // Also check sitemap_index.xml
        if (sitemapRes.body.includes('sitemapindex')) {
          const subSitemaps = [...sitemapRes.body.matchAll(/<loc>([^<]*sitemap[^<]*)<\/loc>/gi)].map(m => m[1]).slice(0, 5);
          for (const sub of subSitemaps) {
            try {
              const subRes = await safeGet(sub, 5000);
              this.requestsMade++;
              if (subRes?.ok) {
                const subLocs = [...subRes.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]).slice(0, 50);
                subLocs.forEach(l => { try { discoveredPaths.add(new URL(l).pathname); sources.sitemap++; } catch {} });
              }
            } catch {}
          }
        }
      }
    } catch {}

    // === 2. Robots.txt parsing ===
    try {
      const robotsRes = await safeGet(`${targetBase}/robots.txt`, 8000);
      this.requestsMade++;
      if (robotsRes?.ok && robotsRes.body.length > 10) {
        const lines = robotsRes.body.split('\n');
        const disallowPaths: string[] = [];
        const sensitivePaths: string[] = [];
        const SENSITIVE_PATTERNS = ['admin', 'config', 'backup', '.env', 'private', 'secret', 'internal', 'debug', 'database', 'dump', 'api', 'cgi-bin'];

        for (const line of lines) {
          const match = line.match(/^Disallow:\s*(.+)/i);
          if (match) {
            const p = match[1].trim();
            if (p && p !== '/') {
              disallowPaths.push(p);
              discoveredPaths.add(p);
              sources.robots++;
              if (SENSITIVE_PATTERNS.some(pat => p.toLowerCase().includes(pat))) {
                sensitivePaths.push(p);
              }
              const dir = p.endsWith('/') ? p : p.split('/').slice(0, -1).join('/') || '/';
              discoveredDirs.add(dir);
            }
          }
        }

        robotsAnalysis = {
          accessible: true,
          content_length: robotsRes.body.length,
          lines_count: lines.length,
          disallow_paths: disallowPaths,
          sensitive_paths: sensitivePaths,
          security_findings: sensitivePaths.length > 0 ? [`${sensitivePaths.length} sensitive paths disclosed in robots.txt`] : [],
        };

        if (sensitivePaths.length > 0) {
          this.addFinding({ id: 'robots-sensitive', title: 'Sensitive Paths in robots.txt', category: 'disclosure', severity: 'low',
            description: `robots.txt discloses ${sensitivePaths.length} sensitive paths: ${sensitivePaths.slice(0, 5).join(', ')}`,
            evidence: { url: `${targetBase}/robots.txt`, paths: sensitivePaths },
            impact: 'Attackers can discover hidden admin/config paths', recommendation: 'Review robots.txt disclosure — consider removing sensitive paths' });
        }
      }
    } catch {}

    // === 3. Deep JS Mining (parallel batches of 5) ===
    const jsRoutes = new Set<string>();
    if (htmlBody) {
      const jsUrls = [...htmlBody.matchAll(/src="([^"]*\.js[^"]*)"/gi)].map(m => m[1]).slice(0, 15);

      await parallelBatch(jsUrls, 5, async (jsUrl) => {
        try {
          const fullUrl = jsUrl.startsWith('http') ? jsUrl : `${targetBase}${jsUrl.startsWith('/') ? '' : '/'}${jsUrl}`;
          const jsRes = await safeGet(fullUrl, 6000);
          this.requestsMade++;
          if (jsRes?.ok && jsRes.body) {
            const patterns = [
              /"(\/api\/[^"]{2,60})"/g,
              /path:\s*["']([^"']{2,60})["']/g,
              /route:\s*["']([^"']{2,60})["']/g,
              /["'](\/(?:admin|debug|internal|config|api|graphql|dashboard|settings|users)[^"']{0,50})["']/g,
            ];
            for (const pattern of patterns) {
              const matches = [...jsRes.body.matchAll(pattern)].map(m => m[1]).slice(0, 15);
              matches.forEach(r => { if (r.startsWith('/') && r.length < 80) jsRoutes.add(r); });
            }

            // Source maps
            if (jsRes.body.includes('sourceMappingURL') || jsRes.headers['sourcemap']) {
              const mapUrl = `${fullUrl}.map`;
              const mapRes = await safeFetch(mapUrl, { method: 'HEAD', timeout: 4000 });
              this.requestsMade++;
              if (mapRes?.ok) {
                exposures.push({ path: mapUrl.replace(targetBase, ''), status_code: 200, severity: 'medium', source: 'js_analysis',
                  exposure: 'JavaScript source map publicly accessible', accessible: true, evidence: { url: mapUrl, status: 200 } });
                this.addFinding({ id: `sourcemap-${jsUrl.split('/').pop()}`, title: 'Source Map Exposed', category: 'disclosure', severity: 'medium',
                  description: `Source map file accessible: ${mapUrl}`, evidence: { url: mapUrl, status: 200 },
                  impact: 'Original source code visible to attackers', recommendation: 'Remove source maps from production' });
              }
            }
          }
        } catch {}
      });

      for (const route of jsRoutes) { discoveredPaths.add(route); sources.js_analysis++; }
    }

    // === 4. Derivative inference ===
    const derivatives = new Set<string>();
    for (const path of discoveredPaths) {
      if (path.includes('/api/v1/')) derivatives.add(path.replace('/api/v1/', '/api/v1/admin/'));
      if (path.includes('/api/')) derivatives.add(path.replace(/\/api\/.*/, '/api/debug'));
    }
    for (const d of derivatives) discoveredPaths.add(d);

    // === 5. Framework-specific paths ===
    const frameworkPaths: string[] = [];
    const fw = technologies?.framework?.toLowerCase() || '';
    const srvr = technologies?.server?.toLowerCase() || '';
    if (fw.includes('spring') || htmlBody?.includes('actuator')) {
      frameworkPaths.push('/actuator', '/actuator/health', '/actuator/env', '/actuator/beans', '/actuator/configprops', '/actuator/mappings');
    }
    if (fw.includes('laravel')) {
      frameworkPaths.push('/storage/logs', '/storage/logs/laravel.log', '/bootstrap/cache', '/public/storage');
    }
    if (fw.includes('django') || htmlBody?.includes('csrfmiddlewaretoken')) {
      frameworkPaths.push('/static/admin/', '/media/', '/graphql', '/admin/');
    }
    if (fw.includes('wordpress') || htmlBody?.includes('wp-content')) {
      frameworkPaths.push('/wp-admin/', '/wp-json/', '/wp-json/wp/v2/users', '/wp-content/debug.log', '/wp-config.php.bak', '/xmlrpc.php');
    }
    if (srvr.includes('nginx')) frameworkPaths.push('/nginx.conf', '/conf/nginx.conf');
    if (srvr.includes('apache')) frameworkPaths.push('/server-status', '/server-info', '/.htpasswd');
    for (const p of frameworkPaths) { discoveredPaths.add(p); sources.framework++; }

    // === 6. Static sensitive paths ===
    const STATIC_PATHS = [
      '/.env', '/.env.local', '/.env.production', '/.env.example', '/config.json', '/settings.json', '/secrets.json',
      '/admin', '/administrator', '/wp-admin', '/wp-login.php', '/login', '/dashboard',
      '/api', '/api/v1', '/api/health', '/api/docs', '/swagger', '/swagger-ui.html', '/graphql',
      '/.git/config', '/.git/HEAD', '/.svn/entries', '/.hg/', '/debug', '/phpinfo.php',
      '/backup.zip', '/backup.sql', '/db.sql', '/dump.sql', '/database.sql',
      '/package.json', '/composer.json', '/Gemfile', '/requirements.txt', '/web.config', '/.htaccess',
      '/.well-known/security.txt', '/humans.txt', '/crossdomain.xml', '/clientaccesspolicy.xml',
      '/.DS_Store', '/Thumbs.db', '/.dockerenv', '/docker-compose.yml', '/Dockerfile',
      '/info.php', '/test.php', '/error_log', '/errors.log',
    ];
    for (const p of STATIC_PATHS) { discoveredPaths.add(p); sources.static++; }

    // === 7. Extension-based file discovery per directory ===
    const EXTENSIONS = ['.env', '.env.local', '.env.bak', 'config.json', 'settings.yml', '.bak', '.old', '.zip', '.sql', '.map', 'package.json', 'tsconfig.json', 'vite.config.js', 'webpack.config.js'];
    const dirList = [...discoveredDirs].slice(0, 15);
    for (const dir of dirList) {
      const base = dir.endsWith('/') ? dir : `${dir}/`;
      for (const ext of EXTENSIONS) {
        const testPath = ext.startsWith('.') ? `${base}${ext}` : `${base}${ext}`;
        discoveredPaths.add(testPath);
        sources.extension++;
      }
    }

    // === 8. Test all discovered paths via HEAD (parallel batches of 15) ===
    // First, get homepage fingerprint to detect SPA fallback (returns index.html for all paths)
    const homepageRes = await safeFetch(targetBase, { method: 'HEAD', timeout: 5000 });
    const homepageContentType = homepageRes?.headers['content-type'] || '';
    const homepageContentLength = homepageRes?.headers['content-length'] || '';
    const isSpaLikely = homepageContentType.includes('text/html');

        // Deduplicate: remove locale/intl variants and limit similar paths
    const seenBases = new Set<string>();
    const filteredPaths = [...discoveredPaths].filter(p => {
      // Skip /intl/ locale variants (e.g. /intl/de/forms/about/)
      if (p.match(/\/intl\/[a-z_-]+\//i)) return false;
      // Skip query-string variants
      if (p.includes('?')) return false;
      // Deduplicate by base path (first 2 segments)
      const base = p.split('/').slice(0, 3).join('/');
      if (seenBases.has(base) && seenBases.size > 30) return false;
      seenBases.add(base);
      return true;
    });
    const uniquePaths = filteredPaths.slice(0, 150);
    const pathResults = await parallelBatch(uniquePaths, 15, async (path) => {
      const fullUrl = path.startsWith('http') ? path : `${targetBase}${path.startsWith('/') ? '' : '/'}${path}`;
      const res = await safeFetch(fullUrl, { method: 'HEAD', timeout: 4000 });
      this.requestsMade++;
      return { path, fullUrl, res };
    });

    totalTested = pathResults.length;
    for (const pr of pathResults) {
      if (!pr?.res) continue;
      const { path, fullUrl, res } = pr;

      if (res.status === 403) wafCount++;

      if (res.status === 200 || res.status === 401 || res.status === 403) {
        // SPA fallback detection: if response looks like homepage (same content-type + content-length), skip
        const isLikelySpaFallback = isSpaLikely && res.status === 200
          && res.headers['content-type']?.includes('text/html')
          && homepageContentLength && res.headers['content-length'] === homepageContentLength
          && !path.match(/\.(env|git|sql|bak|zip|log|cfg|conf|key|pem|json|yml|yaml|xml|map|php|asp|jsp)$/i)
          && !path.includes('.env') && !path.includes('.git');

        if (isLikelySpaFallback) continue; // Skip SPA fallback pages

        // For critical files, do a GET to verify it's real content (not SPA fallback)
        const isCriticalPath = ['.env', '.git', 'secrets', 'backup.sql', 'dump.sql', 'db.sql', 'wp-config', '.htpasswd', 'docker-compose'].some(s => path.includes(s));
        let reallyAccessible = res.status === 200;

        if (isCriticalPath && res.status === 200) {
          // Double-check with GET to see if content is real or SPA HTML
          const getCheck = await safeGet(fullUrl, 4000);
          this.requestsMade++;
          if (getCheck?.ok && getCheck.body) {
            const bodyLower = getCheck.body.toLowerCase();
            // If it returns HTML with typical SPA markers, it's a fallback
            if (bodyLower.includes('<!doctype html') && (bodyLower.includes('id="root"') || bodyLower.includes('id="app"') || bodyLower.includes('script src'))) {
              reallyAccessible = false;
            }
          }
        }

        if (!reallyAccessible && res.status === 200) continue; // Skip false positive

        const severity: string = res.status === 200 && isCriticalPath ? 'critical'
          : res.status === 200 && (path.includes('admin') || path.includes('.sql') || path.includes('.bak')) ? 'medium'
          : res.status === 200 ? 'low' : 'info';

        const pathSource = jsRoutes.has(path) ? 'js_analysis' : frameworkPaths.includes(path) ? 'framework' : STATIC_PATHS.includes(path) ? 'static' : 'discovery';

        if (!exposures.find(e => e.path === path)) {
          exposures.push({
            path, status_code: res.status, severity, source: pathSource,
            exposure: `${path} returns HTTP ${res.status}`,
            risk_summary: res.status === 200 ? 'Publicly accessible' : 'Exists but access restricted',
            accessible: res.status === 200,
            evidence: { url: fullUrl, status: res.status, content_type: res.headers['content-type'] },
          });
        }

        // Add as finding if critical/high
        if (severity === 'critical' || severity === 'high') {
          this.addFinding({ id: `exposure-${path.replace(/[^a-z0-9]/gi, '-')}`, title: `Sensitive File Exposed: ${path}`,
            category: 'disclosure', severity,
            description: `${path} is accessible (HTTP ${res.status}).`,
            impact: 'Sensitive data or configuration may be exposed',
            recommendation: `Restrict access to ${path} or remove it from the web server`,
            evidence: { url: fullUrl, status: res.status } });
        }
      }
    }

    // Directory listing check (only on dirs that returned 200, max 5)
    const dirHits = pathResults.filter(pr => pr?.res?.status === 200 && pr.path.endsWith('/')).slice(0, 5);
    await parallelBatch(dirHits, 5, async (pr) => {
      const getRes = await safeGet(pr!.fullUrl, 4000);
      this.requestsMade++;
      if (getRes?.ok && /Index of|Directory listing|Parent Directory/i.test(getRes.body)) {
        this.addFinding({ id: `dirlist-${pr!.path.replace(/\//g, '-')}`, title: 'Directory Listing Enabled', category: 'disclosure', severity: 'medium',
          description: `Directory listing enabled at ${pr!.path}`, evidence: { url: pr!.fullUrl, status: 200 },
          impact: 'Server file structure visible to attackers', recommendation: 'Disable directory listing in web server config' });
      }
    });

    // WAF detection from high 403 rate
    const wafDetected = totalTested > 10 && wafCount / totalTested > 0.5;
    const metrics = {
      total_paths_tested: totalTested,
      total_directories_analyzed: dirList.length,
      discovery_sources: sources,
      waf_indicators: { count_403: wafCount, total_tested: totalTested, waf_detected: wafDetected },
      confidence_level: totalTested > 100 ? 'High' : totalTested > 30 ? 'Medium' : 'Low',
    };

    return { exposures, metrics, robotsAnalysis };
  }

  /**
   * CRAWL: Spider pages up to maxPages/maxDepth.
   */
  private async crawl(baseUrl: string, domain: string, maxPages: number, maxDepth: number) {
    const visited = new Set<string>();
    // Follow redirects to find the actual start URL
    let startUrl = baseUrl.startsWith('http') ? baseUrl : `https://${domain}`;
    try {
      const probe = await fetch(startUrl, { redirect: 'follow', signal: AbortSignal.timeout(8000) });
      if (probe.url && probe.url !== startUrl) {
        startUrl = probe.url;
        // Update domain to include www if redirected
        try { const u = new URL(startUrl); if (u.hostname.includes(domain)) domain = u.hostname; } catch {}
      }
      await probe.text().catch(() => {});
    } catch {}
    const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }];
    let totalForms = 0, totalInputs = 0, adminFound = 0, authFound = false;

    while (queue.length > 0 && this.pagesScanned < maxPages) {
      const { url, depth } = queue.shift()!;
      if (visited.has(url) || depth > maxDepth) continue;
      visited.add(url);

      const res = await safeGet(url, 8000);
      this.requestsMade++;
      if (!res?.ok || !res.headers['content-type']?.includes('text/html')) continue;
      this.pagesScanned++;

      const html = res.body;

      // Count forms
      const forms = (html.match(/<form/gi) || []).length;
      totalForms += forms;

      // Count inputs
      const inputs = (html.match(/<input/gi) || []).length;
      totalInputs += inputs;

      // Login detection
      if (/login|signin|sign-in|password/i.test(html)) authFound = true;

      // Admin path detection in links
      if (/\/admin|\/dashboard|\/panel/i.test(html)) adminFound++;

      // External scripts without SRI
      const extScripts = [...html.matchAll(/<script[^>]+src="(https?:\/\/[^"]*)"[^>]*>/gi)];
      const sriMissing = extScripts.filter(m => !m[0].includes('integrity')).length;
      if (sriMissing > 0 && !this.allFindings.find(f => f.id === 'no-sri')) {
        this.addFinding({ id: 'no-sri', title: 'External Scripts Without SRI', category: 'content', severity: 'medium',
          description: `${sriMissing} external scripts loaded without Subresource Integrity hashes.`,
          evidence: { url, count: sriMissing } });
      }

      // Extract links for crawling
      const links = [...html.matchAll(/href="(https?:\/\/[^"]*?)"/g)]
        .map(m => m[1])
        .filter(l => l.includes(domain) && !visited.has(l) && !l.includes('#'))
        .slice(0, 20);

      for (const link of links) {
        queue.push({ url: link, depth: depth + 1 });
      }

      await sleep(50); // Faster crawling
    }

    return {
      attackSurface: {
        total_pages: this.pagesScanned,
        total_forms: totalForms,
        total_inputs: totalInputs,
        total_cookies: 0, // Set from cookie stage
        total_endpoints: 0,
        authentication_found: authFound,
        admin_panels_found: adminFound,
        mixed_content_count: 0,
      },
    };
  }

  /**
   * Detect technologies from headers and body.
   */
  private detectTechnologies(headers: Record<string, string>, body: string): any {
    const tech: any = { server: null, framework: null, cdn: null, waf: null, libraries: [] };
    if (headers['server']) tech.server = headers['server'];
    if (headers['x-powered-by']) tech.framework = headers['x-powered-by'];

    // CDN detection
    if (headers['cf-ray'] || headers['cf-cache-status']) tech.cdn = 'Cloudflare';
    else if (headers['x-amz-cf-id']) tech.cdn = 'CloudFront';
    else if (headers['x-fastly-request-id']) tech.cdn = 'Fastly';

    // WAF detection
    if (headers['cf-ray']) tech.waf = 'Cloudflare WAF';

    // Framework detection from body
    if (body.includes('__next')) tech.framework = tech.framework || 'Next.js';
    else if (body.includes('__nuxt')) tech.framework = tech.framework || 'Nuxt.js';
    else if (body.includes('data-reactroot') || body.includes('_reactRootContainer')) tech.libraries.push('React');
    else if (body.includes('ng-version') || body.includes('ng-app')) tech.libraries.push('Angular');
    else if (body.includes('data-v-') || body.includes('Vue.js')) tech.libraries.push('Vue.js');

    if (body.includes('wp-content') || body.includes('wp-includes')) tech.framework = tech.framework || 'WordPress';
    if (body.includes('jquery')) tech.libraries.push('jQuery');

    return tech;
  }

  /**
   * Additional security rules: HSTS max-age, CSP unsafe-inline, login-over-HTTP,
   * mixed content, basic auth, CORS credentials+wildcard, null origin, error pages, verbose errors.
   */
  private runAdditionalSecurityRules(headers: Record<string, string>, body: string, isHttps: boolean, url: string) {
    // HSTS max-age too short (<6 months = 15768000)
    const hsts = headers['strict-transport-security'] || '';
    if (hsts) {
      const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge > 0 && maxAge < 15768000) {
        this.addFinding({ id: 'hsts-short', title: 'HSTS Max-Age Too Short', category: 'tls', severity: 'low',
          description: `HSTS max-age is ${maxAge} seconds (< 6 months recommended minimum).`,
          evidence: { url, header: hsts }, recommendation: 'Set HSTS max-age to at least 31536000 (1 year)' });
      }
    }

    // CSP with unsafe-inline or unsafe-eval
    const csp = headers['content-security-policy'] || '';
    if (csp) {
      if (csp.includes("'unsafe-inline'")) {
        this.addFinding({ id: 'csp-unsafe-inline', title: 'CSP Allows unsafe-inline', category: 'headers', severity: 'medium',
          description: 'Content-Security-Policy includes unsafe-inline, reducing XSS protection.',
          evidence: { url, csp: csp.slice(0, 200) }, recommendation: 'Replace unsafe-inline with nonce-based CSP' });
      }
      if (csp.includes("'unsafe-eval'")) {
        this.addFinding({ id: 'csp-unsafe-eval', title: 'CSP Allows unsafe-eval', category: 'headers', severity: 'medium',
          description: 'Content-Security-Policy includes unsafe-eval, allowing eval() in scripts.',
          evidence: { url }, recommendation: 'Remove unsafe-eval from CSP directives' });
      }
    }

    // Login form over HTTP
    if (!isHttps && body) {
      const hasLoginForm = /<form[^>]*>[\s\S]*?(password|passwd|login|signin)[\s\S]*?<\/form>/i.test(body);
      if (hasLoginForm) {
        this.addFinding({ id: 'login-over-http', title: 'Login Form Over HTTP', category: 'auth', severity: 'critical',
          description: 'Login form submits credentials over unencrypted HTTP.', evidence: { url },
          impact: 'Credentials transmitted in cleartext, vulnerable to interception',
          recommendation: 'Redirect all login pages to HTTPS', owasp_category: 'A07:2021 Identification and Authentication Failures' });
      }
    }

    // Mixed content detection
    if (isHttps && body) {
      const httpResources = [...body.matchAll(/(?:src|href|action)="(http:\/\/[^"]+)"/gi)].length;
      if (httpResources > 0) {
        this.addFinding({ id: 'mixed-content', title: 'Mixed Content Detected', category: 'content', severity: 'medium',
          description: `${httpResources} HTTP resources loaded on HTTPS page.`,
          evidence: { url, count: httpResources }, recommendation: 'Ensure all resources are loaded over HTTPS' });
      }
    }

    // Basic auth header
    if (headers['www-authenticate']?.toLowerCase().includes('basic')) {
      this.addFinding({ id: 'basic-auth', title: 'HTTP Basic Authentication', category: 'auth', severity: 'medium',
        description: 'Server uses HTTP Basic Authentication (credentials sent base64-encoded).',
        evidence: { url }, recommendation: 'Replace Basic auth with token-based or session-based authentication' });
    }

    // CORS credentials with wildcard
    if (headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'] === 'true') {
      this.addFinding({ id: 'cors-cred-wildcard', title: 'CORS Wildcard with Credentials', category: 'cors', severity: 'high',
        description: 'CORS allows any origin with credentials — critical misconfiguration.',
        evidence: { url }, impact: 'Any website can make authenticated requests', recommendation: 'Restrict CORS origin to specific trusted domains' });
    }

    // CORS null origin
    if (headers['access-control-allow-origin'] === 'null') {
      this.addFinding({ id: 'cors-null', title: 'CORS Allows Null Origin', category: 'cors', severity: 'medium',
        description: 'Access-Control-Allow-Origin is set to null — exploitable from sandboxed iframes.',
        evidence: { url }, recommendation: 'Remove null from allowed origins' });
    }

    // Verbose error pages (stack traces)
    if (body && (/at\s+\w+\s*\(.*:\d+:\d+\)/i.test(body) || /Traceback \(most recent call last\)/i.test(body) || /Fatal error.*on line \d+/i.test(body))) {
      this.addFinding({ id: 'verbose-errors', title: 'Verbose Error Messages', category: 'disclosure', severity: 'medium',
        description: 'Page exposes stack traces or debug information.', evidence: { url },
        impact: 'Internal paths, versions, and code structure visible to attackers',
        recommendation: 'Configure custom error pages for production, disable debug mode' });
    }
  }

  private addFinding(finding: Finding) {
    if (!this.allFindings.find(f => f.id === finding.id)) {
      this.allFindings.push(finding);
    }
  }
}

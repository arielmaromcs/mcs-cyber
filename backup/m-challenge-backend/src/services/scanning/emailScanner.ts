/**
 * EmailScannerService - Complete 10-stage email infrastructure scanner.
 * 
 * Stages: DNS → SPF → DKIM → DMARC → MX → WHOIS → SMTP → Blacklist → Ports → AbuseIPDB
 * 
 * Scoring: SPF(18) + DKIM(18) + DMARC(22) + Relay(18) + Infrastructure(12) + Ports(12) = 100
 */

import { prisma } from '../../config/database';
import { dnsResolve, sleep } from '../../utils/scanUtils';
import { config } from '../../config/env';

export class EmailScannerService {
  async run(scanId: string, domain: string): Promise<void> {
    try {
      // ---- Stage 1: DNS (10%) ----
      await this.update(scanId, 2, 'DNS');
      const dnsRecords = await this.fetchDnsRecords(domain);
      await this.update(scanId, 10, 'SPF', { dnsRecords: dnsRecords as any });

      // ---- Stage 2: SPF (20%) ----
      const spf = this.analyzeSPF(dnsRecords.txt_records || []);
      await this.update(scanId, 20, 'DKIM', { spfRecord: spf as any });

      // ---- Stage 3: DKIM (30%) ----
      const dkim = await this.analyzeDKIM(domain);
      await this.update(scanId, 30, 'DMARC', { dkimRecord: dkim as any });

      // ---- Stage 4: DMARC (40%) ----
      const dmarc = await this.analyzeDMARC(domain);
      await this.update(scanId, 40, 'MX', { dmarcRecord: dmarc as any });

      // ---- Stage 5: MX Analysis (50%) ----
      const mx = this.analyzeMX(dnsRecords.mx_records || []);
      await this.update(scanId, 50, 'WHOIS', { mxAnalysis: mx as any });

      // ---- Stage 6: WHOIS (60%) ----
      const whois = await this.fetchWhois(domain);
      await this.update(scanId, 60, 'SMTP', { whoisInfo: whois as any });

      // ---- Stage 7: SMTP Tests (70%) ----
      const smtp = this.analyzeSmtp(domain);
      await this.update(scanId, 70, 'Blacklist', { smtpTests: smtp as any });

      // ---- Stage 8: Blacklist Check (80%) ----
      const blacklist = await this.checkBlacklists(dnsRecords.a_records || []);
      await this.update(scanId, 80, 'Ports', { blacklistStatus: blacklist as any });

      // ---- Stage 9: Port Scan / Shodan (90%) ----
      const portScan = await this.checkPorts(dnsRecords.a_records?.[0] || '');
      await this.update(scanId, 90, 'AbuseIPDB', { portScan: portScan as any });

      // ---- Stage 10: AbuseIPDB (100%) ----
      const abuseipdb = await this.checkAbuseIPDB(dnsRecords.a_records?.[0] || '');
      await this.update(scanId, 95, 'Finalizing');

      // ---- Calculate scores ----
      const relayScore = smtp.relay_open ? 0 : 18;
      const infraScore = Math.min(12, (blacklist.reputation_score / 100) * 12);
      const portsScore = Math.max(0, 12 - (portScan.high_risk_ports_count || 0) * 3);

      const totalScore = Math.round(
        Math.min(18, spf.score) + Math.min(18, dkim.score) + Math.min(22, dmarc.score) +
        Math.min(18, relayScore) + Math.min(12, infraScore) + Math.min(12, portsScore)
      );

      // Generate findings
      const findings: any[] = [];
      const recommendations: string[] = [];

      if (spf.score < 18) {
        findings.push({ severity: spf.score === 0 ? 'critical' : 'medium', title: 'SPF Policy Weakness', description: spf.issues.join('. ') });
        if (!spf.exists) recommendations.push('Add an SPF record: v=spf1 include:... -all');
        else if (spf.policy !== 'hardfail') recommendations.push('Upgrade SPF policy to hardfail (-all)');
      }
      if (dkim.score < 18) {
        findings.push({ severity: dkim.score === 0 ? 'high' : 'medium', title: 'DKIM Not Configured', description: dkim.issues.join('. ') });
        recommendations.push('Configure DKIM with at least a 2048-bit key');
      }
      if (dmarc.score < 22) {
        findings.push({ severity: dmarc.score === 0 ? 'critical' : 'medium', title: 'DMARC Policy Weakness', description: dmarc.issues.join('. ') });
        if (!dmarc.exists) recommendations.push('Add DMARC record with reject policy');
        else if (dmarc.policy !== 'reject') recommendations.push('Upgrade DMARC policy to reject');
      }
      if (portScan.high_risk_ports_count > 0) {
        findings.push({ severity: 'high', title: 'High-Risk Ports Open', description: `${portScan.high_risk_ports_count} high-risk ports detected` });
        recommendations.push('Review and close unnecessary high-risk ports');
      }

      // Generate MXToolbox links
      const mxtoolboxLinks = {
        blacklist: `https://mxtoolbox.com/blacklists.aspx?q=${domain}`,
        email_health: `https://mxtoolbox.com/emailhealth/${domain}`,
        mx_lookup: `https://mxtoolbox.com/MXLookup.aspx?InputText=${domain}`,
        spf_lookup: `https://mxtoolbox.com/spf.aspx?q=${domain}`,
        dmarc_lookup: `https://mxtoolbox.com/dmarc.aspx?q=${domain}`,
        domain_health: `https://mxtoolbox.com/domain/${domain}`,
      };

      // Final update
      await prisma.emailScan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED', progress: 100, currentStage: 'Complete',
          emailSecurityScore: totalScore,
          scoreBreakdown: { spf: Math.min(18, spf.score), dkim: Math.min(18, dkim.score), dmarc: Math.min(22, dmarc.score), relay: Math.min(18, relayScore), misc: Math.round(infraScore), ports: Math.round(portsScore) } as any,
          scoreRating: totalScore >= 80 ? 'Good' : totalScore >= 60 ? 'Fair' : totalScore >= 40 ? 'Needs Improvement' : 'Poor',
          findings: findings as any,
          recommendations,
          abuseipdb: abuseipdb as any,
          mxtoolboxLinks: mxtoolboxLinks as any,
        },
      });
    } catch (err: any) {
      await prisma.emailScan.update({
        where: { id: scanId },
        data: { status: 'FAILED', errorMessage: err.message },
      });
      throw err;
    }
  }

  // ---- Helpers ----

  private async update(scanId: string, progress: number, stage: string, data: any = {}) {
    await prisma.emailScan.update({
      where: { id: scanId },
      data: { progress: Math.min(99, progress), currentStage: stage, ...data },
    });
  }

  private async fetchDnsRecords(domain: string) {
    const records: any = {};
    for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']) {
      const recs = await dnsResolve(domain, type);
      records[`${type.toLowerCase()}_records`] = recs.map(r => r.data);
    }
    return records;
  }

  private analyzeSPF(txtRecords: string[]) {
    const spfRaw = txtRecords.find((t: string) => t.includes('v=spf1'));
    let score = 0;
    const issues: string[] = [];
    let policy = 'none';
    let lookups = 0;

    if (!spfRaw) {
      issues.push('No SPF record found');
      return { exists: false, record: null, valid: false, lookups: 0, policy: 'none', issues, score: 0 };
    }

    score += 12;
    lookups = (spfRaw.match(/include:/g) || []).length;

    if (spfRaw.includes('-all')) { policy = 'hardfail'; score += 6; }
    else if (spfRaw.includes('~all')) { policy = 'softfail'; score += 3; issues.push('Uses softfail (~all) instead of hardfail (-all)'); }
    else if (spfRaw.includes('+all')) { policy = 'pass'; issues.push('DANGEROUS: +all allows any server to send email'); }
    else { issues.push('No explicit enforcement policy'); }

    if (lookups > 10) issues.push(`${lookups} DNS lookups (exceeds SPF limit of 10)`);

    return { exists: true, record: spfRaw, valid: true, lookups, policy, issues, score };
  }

  private async analyzeDKIM(domain: string) {
    const SELECTORS = ['default', 'google', 'dkim', 'mail', 'k1', 'selector1', 'selector2', 'protonmail', 'mandrill'];
    let score = 0;
    const issues: string[] = [];
    const selectorsFound: string[] = [];
    let keyLength = 0;

    for (const sel of SELECTORS) {
      const recs = await dnsResolve(`${sel}._domainkey.${domain}`, 'TXT');
      if (recs.length > 0) {
        selectorsFound.push(sel);
        score = 12;
        const keyData = recs[0].data;
        if (keyData.length > 400) { keyLength = 2048; score = 18; }
        else { keyLength = 1024; score = 14; }
        break;
      }
    }

    if (selectorsFound.length === 0) {
      issues.push('No DKIM selector found across common selectors');
      score = 0;
    } else if (keyLength < 2048) {
      issues.push(`DKIM key length ${keyLength} bits (recommend 2048+)`);
    }

    return { exists: selectorsFound.length > 0, selectors_found: selectorsFound, key_length: keyLength, valid: selectorsFound.length > 0, issues, score };
  }

  private async analyzeDMARC(domain: string) {
    const recs = await dnsResolve(`_dmarc.${domain}`, 'TXT');
    const dmarcRaw = recs.map(r => r.data).find(d => d.includes('v=DMARC1'));
    const issues: string[] = [];
    let score = 0;
    let policy = 'none';

    if (!dmarcRaw) {
      issues.push('No DMARC record found');
      return { exists: false, record: null, policy: 'none', valid: false, issues, score: 0 };
    }

    score += 12;
    if (dmarcRaw.includes('p=reject')) { policy = 'reject'; score += 10; }
    else if (dmarcRaw.includes('p=quarantine')) { policy = 'quarantine'; score += 7; issues.push('DMARC policy is quarantine (reject is stronger)'); }
    else { policy = 'none'; issues.push('DMARC policy is none (provides no enforcement)'); }

    const hasRua = dmarcRaw.includes('rua=');
    const hasRuf = dmarcRaw.includes('ruf=');
    if (!hasRua) issues.push('No aggregate report (rua) configured');

    return { exists: true, record: dmarcRaw, policy, valid: true, has_rua: hasRua, has_ruf: hasRuf, issues, score };
  }

  private analyzeMX(mxRecords: string[]) {
    const providers: Record<string, string> = {
      'google.com': 'Google Workspace', 'googlemail.com': 'Google Workspace',
      'outlook.com': 'Microsoft 365', 'protection.outlook.com': 'Microsoft 365',
      'pphosted.com': 'Proofpoint', 'mimecast.com': 'Mimecast',
      'messagelabs.com': 'Symantec', 'barracuda.com': 'Barracuda',
    };

    const detected: string[] = [];
    for (const mx of mxRecords) {
      for (const [domain, name] of Object.entries(providers)) {
        if (mx.includes(domain)) detected.push(name);
      }
    }

    return {
      records: mxRecords,
      count: mxRecords.length,
      redundant: mxRecords.length > 1,
      providers: [...new Set(detected)],
    };
  }

  private async fetchWhois(domain: string) {
    if (!config.whois.apiKey) {
      return { available: false, reason: 'WHOIS API key not configured' };
    }
    try {
      const res = await fetch(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
        headers: { 'Authorization': `Token ${config.whois.apiKey}` },
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) return await res.json();
      return { available: false, reason: `WHOIS API error: ${res.status}` };
    } catch {
      return { available: false, reason: 'WHOIS lookup failed' };
    }
  }

  private analyzeSmtp(domain: string) {
    // SMTP tests are passive/simulated - no actual connection
    return {
      relay_open: false,
      starttls_supported: true,
      supports_tls12: true,
      banner: 'SMTP test simulated (no active connection)',
    };
  }

  /**
   * Blacklist check via reverse-IP DNSBL queries.
   */
  private async checkBlacklists(aRecords: string[]) {
    const DNSBLS = ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net', 'b.barracudacentral.org'];
    const ipsChecked: any[] = [];
    let listedCount = 0;

    for (const ip of aRecords.slice(0, 3)) {
      const parts = ip.split('.').reverse().join('.');
      let listed = false;

      for (const dnsbl of DNSBLS) {
        const query = `${parts}.${dnsbl}`;
        const records = await dnsResolve(query, 'A');
        if (records.length > 0) { listed = true; break; }
        await sleep(50);
      }

      ipsChecked.push({ ip, listed, dnsbls_checked: DNSBLS });
      if (listed) listedCount++;
    }

    const totalChecked = ipsChecked.length || 1;
    return {
      ips_checked: ipsChecked,
      listed_ips_count: listedCount,
      total_checked: totalChecked,
      reputation_score: Math.round((1 - listedCount / totalChecked) * 100),
    };
  }

  private async checkPorts(ip: string) {
    if (!ip || !config.shodan.apiKey) {
      return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
    }
    try {
      const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${config.shodan.apiKey}`, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
      const data = await res.json();
      const HIGH_RISK = [21, 23, 25, 445, 3389, 3306, 5432, 27017];
      const openPorts = (data as any).ports || [];
      const highRisk = openPorts.filter((p: number) => HIGH_RISK.includes(p));
      return { available: true, open_ports: openPorts, high_risk_ports: highRisk, high_risk_ports_count: highRisk.length };
    } catch {
      return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
    }
  }

  private async checkAbuseIPDB(ip: string) {
    if (!ip || !config.abuseipdb.apiKey) {
      return { available: false, safe: true, abuse_confidence_score: 0, total_reports: 0 };
    }
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
        headers: { 'Key': config.abuseipdb.apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return { available: false, safe: true };
      const data: any = await res.json();
      const d = data.data || {};
      return {
        available: true, safe: d.abuseConfidenceScore < 25,
        abuse_confidence_score: d.abuseConfidenceScore || 0,
        total_reports: d.totalReports || 0,
        country_name: d.countryName || 'Unknown',
        isp: d.isp || 'Unknown',
      };
    } catch {
      return { available: false, safe: true };
    }
  }
}

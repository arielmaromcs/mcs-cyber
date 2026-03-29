/**
 * EmailScannerService - Complete 10-stage email infrastructure scanner.
 * Stages: DNS → SPF → DKIM → DMARC → MX → WHOIS → SMTP → Blacklist → Ports → AbuseIPDB
 * Scoring: SPF(18) + DKIM(18) + DMARC(22) + Relay(18) + Infrastructure(12) + Ports(12) = 100
 */
import { prisma } from '../../config/database';
import { EmailService } from '../email/emailService';
import { dnsResolve, sleep } from '../../utils/scanUtils';
import { config } from '../../config/env';

export class EmailScannerService {
  async run(scanId: string, domain: string): Promise<void> {
    try {
      // ---- Stage 1: DNS (10%) ----
      await this.update(scanId, 5, 'DNS_LOOKUP');
      const dnsRecords = await this.fetchDnsRecords(domain);
      await this.update(scanId, 15, 'SPF_ANALYSIS', { dnsRecords: dnsRecords as any });

      // ---- Stage 2: SPF (25%) ----
      const spf = this.analyzeSPF(dnsRecords.txt_records || []);
      await this.update(scanId, 25, 'DKIM_ANALYSIS', { spfRecord: spf as any });

      // ---- Stage 3: DKIM (35%) ----
      const dkim = await this.analyzeDKIM(domain);
      await this.update(scanId, 35, 'DMARC_ANALYSIS', { dkimRecord: dkim as any });

      // ---- Stage 4: DMARC (45%) ----
      const dmarc = await this.analyzeDMARC(domain);
      await this.update(scanId, 45, 'MX_ANALYSIS', { dmarcRecord: dmarc as any });

      // ---- Stage 5: MX Analysis (55%) ----
      const mx = this.analyzeMX(dnsRecords.mx_records || []);
      await this.update(scanId, 55, 'WHOIS', { mxAnalysis: mx as any });

      // ---- Stage 6: WHOIS (65%) ----
      const whois = await this.fetchWhois(domain);
      await this.update(scanId, 65, 'SMTP_CAPABILITY', { whoisInfo: whois as any });

      // ---- Stage 7: SMTP Tests (72%) ----
      const smtp = this.analyzeSmtp(domain, mx);
      const rawMx = mx.records?.[0] || '';
      const mxHost = rawMx.replace(/^\d+\s+/, '').replace(/\.$/, '').trim();
      const relayTest = await this.testMailRelay(domain, mxHost);
      const smtpCombined = { ...smtp, ...relayTest };
      await this.update(scanId, 72, 'BLACKLIST_CHECK', { smtpTests: smtpCombined as any });

      // ---- Stage 8: Blacklist Check (82%) ----
      const blacklist = await this.checkBlacklists(dnsRecords.a_records || [], mx);
      await this.update(scanId, 82, 'PORT_SCAN', { blacklistStatus: blacklist as any });

      // ---- Stage 9: Port Scan (90%) ----
      const portScan = await this.checkPorts(dnsRecords.a_records?.[0] || '');
      await this.update(scanId, 90, 'ABUSEIPDB', { portScan: portScan as any });

      // ---- Stage 10: AbuseIPDB (95%) ----
      const abuseipdb = await this.checkAbuseIPDB(dnsRecords.a_records?.[0] || '');
      await this.update(scanId, 95, 'FINALIZATION', { abuseipdb: abuseipdb as any });

      // ---- Calculate scores (spec-exact) ----
      const spfScore = spf.exists ? (spf.issues.length === 0 ? 18 : 12) : 0;
      const dkimScore = dkim.exists ? (dkim.key_length >= 2048 ? 18 : 14) : 0;
      let dmarcScore = 0;
      if (dmarc.policy === 'reject') dmarcScore = 22;
      else if (dmarc.policy === 'quarantine') dmarcScore = 15;
      else if (dmarc.policy === 'none') dmarcScore = 8;
      const relayScore = relayTest.relay_open ? 0 : 18;
      let miscScore = 0;
      if (mx.exists) miscScore += 4;
      if (whois.status === 'success') miscScore += 4;
      if (smtp.starttls_supported) miscScore += 4;
      const portsScore = 12 - Math.min(12, (portScan.high_risk_ports_count || 0) * 3);

      const totalScore = Math.round(
        Math.min(18, spfScore) + Math.min(18, dkimScore) + Math.min(22, dmarcScore) +
        Math.min(18, relayScore) + Math.min(12, miscScore) + Math.min(12, portsScore)
      );

      // Hebrew rating
      let rating = 'בעייתי';
      if (totalScore >= 90) rating = 'מצוין';
      else if (totalScore >= 70) rating = 'טוב';
      else if (totalScore >= 50) rating = 'סביר';

      // Generate findings
      const findings: any[] = [];
      const recommendations: string[] = [];

      if (!spf.exists) {
        findings.push({ severity: 'critical', title: 'SPF Record Missing', description: 'No SPF record found for this domain' });
        recommendations.push('Add an SPF record: v=spf1 include:... -all');
      } else if (spf.issues.length > 0) {
        findings.push({ severity: 'medium', title: 'SPF Policy Weakness', description: spf.issues.join('. ') });
        if (spf.policy !== 'hardfail') recommendations.push('Upgrade SPF policy to hardfail (-all)');
      }
      if (!dkim.exists) {
        findings.push({ severity: 'high', title: 'DKIM Not Configured', description: 'No DKIM selector found across common selectors' });
        recommendations.push('Configure DKIM with at least a 2048-bit key');
      } else if (dkim.key_length < 2048) {
        findings.push({ severity: 'medium', title: 'DKIM Key Too Short', description: `DKIM key is ${dkim.key_length}-bit - consider upgrading to 2048-bit` });
        recommendations.push('Upgrade DKIM key to 2048-bit');
      }
      if (!dmarc.exists) {
        findings.push({ severity: 'critical', title: 'DMARC Record Missing', description: 'No DMARC record found' });
        recommendations.push('Add DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com');
      } else if (dmarc.policy !== 'reject') {
        findings.push({ severity: 'medium', title: 'DMARC Policy Weakness', description: dmarc.issues.join('. ') });
        recommendations.push('Upgrade DMARC policy to reject');
      }
      if (blacklist.listed_ips_count > 0) {
        findings.push({ severity: 'high', title: 'IP Blacklisted', description: `${blacklist.listed_ips_count} IP(s) found on DNS blacklists` });
        recommendations.push('Investigate and request delisting from blacklists');
      }
      if (portScan.high_risk_ports_count > 0) {
        findings.push({ severity: 'high', title: 'High-Risk Ports Open', description: `${portScan.high_risk_ports_count} high-risk ports detected` });
        recommendations.push('Review and close unnecessary high-risk ports');
      }
      if (!smtp.starttls_supported) {
        findings.push({ severity: 'medium', title: 'STARTTLS Not Supported', description: 'Mail server does not support encrypted connections' });
        recommendations.push('Enable STARTTLS on your mail server');
      }

      // MXToolbox links (spec-exact format)
      const ip = dnsRecords.a_records?.[0] || domain;
      const mxtoolboxLinks = {
        blacklist_check: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${ip}`,
        mx_lookup: `https://mxtoolbox.com/SuperTool.aspx?action=mx:${domain}`,
        spf_lookup: `https://mxtoolbox.com/SuperTool.aspx?action=spf:${domain}`,
        dmarc_lookup: `https://mxtoolbox.com/SuperTool.aspx?action=dmarc:${domain}`,
        dkim_lookup: `https://mxtoolbox.com/SuperTool.aspx?action=dkim:default._domainkey.${domain}`,
        email_health: `https://mxtoolbox.com/EmailHealth.aspx?domain=${domain}`,
        domain_health: `https://mxtoolbox.com/SuperTool.aspx?action=dns:${domain}`,
      };

      // Final update
      await prisma.emailScan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED', progress: 100, currentStage: 'COMPLETE',
          emailSecurityScore: totalScore,
          scoreBreakdown: { spf: Math.min(18, spfScore), dkim: Math.min(18, dkimScore), dmarc: Math.min(22, dmarcScore), relay: Math.min(18, relayScore), misc: Math.min(12, miscScore), ports: Math.min(12, portsScore) } as any,
          scoreRating: rating,
          findings: findings as any,
          recommendations,
          abuseipdb: abuseipdb as any,
          mxtoolboxLinks: mxtoolboxLinks as any,
        },
      });
      // Send email notification only if triggered by scheduler
      if ((this as any)._fromSchedule) {
      try {
        {
          const schedules = await prisma.emailScanSchedule.findMany({
            where: { domain, isActive: true, notifyOnComplete: true },
          });
          for (const sched of schedules) {
            if (sched.notifyEmails?.length > 0) {
              const emailSvc = new EmailService();
              let clientName = '';
              if ((sched as any).customerId) {
                const client = await (prisma as any).$queryRaw`SELECT name FROM clients WHERE id = ${(sched as any).customerId} LIMIT 1`;
                clientName = (client as any[])[0]?.name || '';
              }
              const descWithClient = clientName ? (sched.description ? clientName + ' — ' + sched.description : clientName) : (sched.description || undefined);
              await emailSvc.sendScanNotification(
                sched.notifyEmails.filter(Boolean),
                domain, 'Email Security', totalScore, undefined,
                { findings, recommendations, scoreBreakdown: { spf: Math.min(18, spfScore), dkim: Math.min(18, dkimScore), dmarc: Math.min(22, dmarcScore), relay: Math.min(18, relayScore), misc: Math.min(12, miscScore), ports: Math.min(12, portsScore) }, rating, description: descWithClient }
              );
              console.log('[EmailScanner] Notification sent to:', sched.notifyEmails);
            }
          }
        }
      } catch (notifErr: any) { console.error('[EmailScanner] Notification error:', notifErr.message); }
      } // end fromSchedule check
    } catch (err: any) {
      await prisma.emailScan.update({
        where: { id: scanId },
        data: { status: 'FAILED', errorMessage: err.message },
      }).catch(() => {});
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
    const records: any = { a_records: [], aaaa_records: [], mx_records: [], ns_records: [], txt_records: [], soa_records: [] };
    for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']) {
      try {
        const recs = await dnsResolve(domain, type);
        records[`${type.toLowerCase()}_records`] = recs.map((r: any) => r.data);
      } catch { /* ignore */ }
    }
    return records;
  }

  // SPF Analysis (spec-exact)
  private analyzeSPF(txtRecords: string[]) {
    const spfRaw = txtRecords.find((t: string) => t.includes('v=spf1'));
    const issues: string[] = [];
    let policy = 'none';
    let lookups = 0;

    if (!spfRaw) {
      return { exists: false, record: null, valid: false, lookups: 0, policy: 'none', status: 'missing', issues: ['No SPF record found'], score: 0 };
    }

    // Check +all (critical risk)
    if (spfRaw.includes('+all')) {
      issues.push('SPF allows all senders (+all) - critical security risk');
    }
    // Check enforcement
    if (spfRaw.includes('-all')) { policy = 'hardfail'; }
    else if (spfRaw.includes('~all')) { policy = 'softfail'; issues.push('SPF should end with -all or ~all'); }
    else if (!spfRaw.includes('+all')) { issues.push('SPF should end with -all or ~all'); }

    // Count DNS lookups
    lookups = (spfRaw.match(/include:/g) || []).length +
              (spfRaw.match(/\ba:/g) || []).length +
              (spfRaw.match(/\bmx:/g) || []).length;
    if (lookups > 10) issues.push(`Too many DNS lookups (${lookups}/10) - SPF will fail`);

    const score = issues.length === 0 ? 18 : 12;
    const status = issues.length === 0 ? 'success' : 'warning';
    return { exists: true, record: spfRaw, valid: true, lookups, policy, status, issues, score };
  }

  // DKIM Analysis (spec-exact selectors)
  private async analyzeDKIM(domain: string) {
    const SELECTORS = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim', 's1', 's2'];
    const issues: string[] = [];
    const selectorsFound: string[] = [];
    let keyLength = 0;
    let score = 0;

    for (const sel of SELECTORS) {
      try {
        const recs = await dnsResolve(`${sel}._domainkey.${domain}`, 'TXT');
        if (recs.length > 0) {
          selectorsFound.push(sel);
          const keyData = recs[0].data || '';
          const keyMatch = keyData.match(/p=([A-Za-z0-9+/=]+)/);
          if (keyMatch && keyMatch[1].length < 300) {
            keyLength = 1024;
            issues.push('DKIM key is 1024-bit - consider upgrading to 2048-bit');
          } else {
            keyLength = 2048;
          }
          break; // first found is enough
        }
      } catch { /* selector not found */ }
    }

    if (selectorsFound.length === 0) {
      issues.push('No DKIM selector found across common selectors');
      score = 0;
    } else {
      score = keyLength >= 2048 ? 18 : 14;
    }

    const status = selectorsFound.length === 0 ? 'missing' : (issues.length === 0 ? 'success' : 'warning');
    return { exists: selectorsFound.length > 0, selectors_found: selectorsFound, key_length: keyLength, valid: selectorsFound.length > 0, status, issues, score };
  }

  // DMARC Analysis (spec-exact)
  private async analyzeDMARC(domain: string) {
    const recs = await dnsResolve(`_dmarc.${domain}`, 'TXT');
    const dmarcRaw = recs.map((r: any) => r.data).find((d: string) => d.includes('v=DMARC1'));
    const issues: string[] = [];
    let policy = 'none';

    if (!dmarcRaw) {
      return { exists: false, record: null, policy: 'none', valid: false, has_rua: false, has_ruf: false, issues: ['No DMARC record found'], score: 0 };
    }

    const policyMatch = dmarcRaw.match(/p=([^;\s]+)/);
    policy = policyMatch ? policyMatch[1].trim() : 'none';

    if (policy === 'none') issues.push('DMARC policy is set to "none" - no enforcement');
    else if (policy === 'quarantine') issues.push('Consider upgrading to "reject" policy');

    const hasRua = dmarcRaw.includes('rua=');
    const hasRuf = dmarcRaw.includes('ruf=');
    if (!hasRua) issues.push('No aggregate report address configured (rua)');

    let score = 0;
    if (policy === 'reject') score = 22;
    else if (policy === 'quarantine') score = 15;
    else if (policy === 'none') score = 8;

    return { exists: true, record: dmarcRaw, policy, valid: true, has_rua: hasRua, has_ruf: hasRuf, issues, score };
  }

  // MX Analysis with provider detection (spec-exact)
  private analyzeMX(mxRecords: string[]) {
    const providers: Record<string, string> = {
      'google.com': 'Google Workspace', 'googlemail.com': 'Google Workspace',
      'outlook.com': 'Microsoft 365', 'protection.outlook.com': 'Microsoft 365',
      'zoho.com': 'Zoho Mail', 'zoho.eu': 'Zoho Mail',
      'pphosted.com': 'Proofpoint', 'mimecast.com': 'Mimecast',
    };
    const detected: string[] = [];
    let provider = 'Unknown';

    for (const mx of mxRecords) {
      const mxLower = (typeof mx === 'string' ? mx : '').toLowerCase();
      for (const [domain, name] of Object.entries(providers)) {
        if (mxLower.includes(domain)) { detected.push(name); provider = name; }
      }
    }

    return {
      exists: mxRecords.length > 0,
      records: mxRecords,
      count: mxRecords.length,
      redundant: mxRecords.length > 1,
      provider,
      providers: [...new Set(detected)],
    };
  }

  // WHOIS via RDAP (spec-exact: free, no API key)
  private async fetchWhois(domain: string) {
    // Try RDAP first (free)
    try {
      const rdap = await fetch(`https://rdap.org/domain/${domain}`, {
        headers: { 'Accept': 'application/rdap+json' },
        signal: AbortSignal.timeout(8000),
      });
      if (rdap.ok) {
        const data: any = await rdap.json();
        const events = data.events || [];
        const getDate = (a: string) => events.find((e: any) => e.eventAction === a)?.eventDate || null;
        const registrar = data.entities?.find((e: any) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'Unknown';
        const ns = (data.nameservers || []).map((n: any) => n.ldhName || '');
        return {
          available: true, status: 'success', registrar,
          created_date: getDate('registration'), expiry_date: getDate('expiration'), updated_date: getDate('last changed'),
          domain_status: (data.status || []).join(', '), name_servers: ns, country: '',
        };
      }
    } catch { /* RDAP failed */ }
    // Fallback: WHOIS API if key exists
    if (config.whois?.apiKey) {
      try {
        const res = await fetch(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
          headers: { 'Authorization': `Token ${config.whois.apiKey}` },
          signal: AbortSignal.timeout(8000),
        });
        if (res.ok) { const d: any = await res.json(); return { ...d, available: true, status: 'success' }; }
      } catch { /* API failed */ }
    }
    // Fallback: NS records only
    const nsRecs = await dnsResolve(domain, 'NS');
    return { available: true, status: 'limited', name_servers: nsRecs.map((r: any) => r.data), registrar: 'Unknown', message: 'WHOIS data limited' };
  }

  // SMTP (simulated, spec-exact)
  private analyzeSmtp(domain: string, mx: any) {
    const firstMx = (mx.records?.[0] || '').toLowerCase();
    if (firstMx.includes('google')) {
      return { relay_open: false, starttls_supported: true, banner: 'Google SMTP', simulated: true };
    }
    if (firstMx.includes('outlook') || firstMx.includes('microsoft')) {
      return { relay_open: false, starttls_supported: true, banner: 'Microsoft SMTP', simulated: true };
    }
    return { relay_open: false, starttls_supported: true, banner: 'Unknown', simulated: true, message: 'SMTP checks are simulated based on mail provider' };
  }


  // Real SMTP Open Relay Test
  async testMailRelay(domain: string, mxHost: string): Promise<{
    relay_open: boolean; starttls_supported: boolean; banner: string;
    log: string[]; recommendations: string[];
  }> {
    const net = await import('net');
    const log: string[] = [];
    let relay_open = false;
    let starttls_supported = false;
    let banner = '';

    if (!mxHost) return { relay_open: false, starttls_supported: false, banner: 'No MX host', log: ['No MX host available'], recommendations: [] };

    return new Promise((resolve) => {
      const timeout = 10000;
      let resolved = false;
      const done = (result: any) => { if (!resolved) { resolved = true; resolve(result); } };
      const buildResult = () => ({
        relay_open, starttls_supported, banner, log,
        recommendations: relay_open ? [
          'סגור מיידית את ה-Open Relay — מאפשר לכל אחד לשלוח מיילים דרך השרת שלך',
          'הגדר mynetworks ב-Postfix/Sendmail לאפשר רק רשתות מורשות',
          'הפעל SMTP Authentication חובה לשולחים חיצוניים',
          'הגדר SPF עם -all כדי למנוע זיוף',
          'בדוק אם השרת כבר ברשימות blacklist עקב שימוש לרעה',
        ] : [],
      });
      try {
        const socket = (net as any).createConnection({ host: mxHost, port: 25, timeout });
        socket.setTimeout(timeout);
        socket.on('timeout', () => { log.push('TIMEOUT'); socket.destroy(); done(buildResult()); });
        socket.on('error', (err: any) => { log.push('ERROR: ' + err.message); done(buildResult()); });
        let step = 0; let buffer = '';
        socket.on('data', (data: Buffer) => {
          buffer += data.toString();
          const lines = buffer.split('\r\n'); buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line) continue;
            log.push('S: ' + line);
            if (step === 0 && line.startsWith('220')) {
              banner = line.substring(4);
              socket.write('EHLO mail-relay-test.m-challenge.com\r\n');
              log.push('C: EHLO mail-relay-test.m-challenge.com');
              step = 1;
            } else if (step === 1) {
              if (line.includes('STARTTLS')) starttls_supported = true;
              if (line.startsWith('250 ') || (line.startsWith('250') && !line.startsWith('250-'))) {
                socket.write('MAIL FROM:<relay-test@m-challenge.com>\r\n');
                log.push('C: MAIL FROM:<relay-test@m-challenge.com>');
                step = 2;
              }
            } else if (step === 2) {
              if (line.startsWith('250')) {
                socket.write('RCPT TO:<test@' + domain + '>\r\n');
                log.push('C: RCPT TO:<test@' + domain + '>');
                step = 3;
              } else { log.push('MAIL FROM rejected'); socket.write('QUIT\r\n'); done(buildResult()); }
            } else if (step === 3) {
              if (line.startsWith('250')) {
                socket.write('DATA\r\n');
                log.push('C: DATA');
                step = 4;
              } else { log.push('RCPT TO rejected - relay blocked: ' + line); socket.write('QUIT\r\n'); done(buildResult()); }
            } else if (step === 4) {
              if (line.startsWith('354')) {
                socket.write('Subject: Relay Test\r\n\r\nRelay test by M-Challenge Security Scanner.\r\n.\r\n');
                log.push('C: DATA body sent');
                step = 5;
              } else { socket.write('QUIT\r\n'); done(buildResult()); }
            } else if (step === 5) {
              if (line.startsWith('250')) { relay_open = true; log.push('!!! OPEN RELAY DETECTED !!!'); }
              socket.write('QUIT\r\n'); log.push('C: QUIT'); done(buildResult());
            }
          }
        });
        socket.on('close', () => { done(buildResult()); });
      } catch (err: any) { log.push('EXCEPTION: ' + err.message); done(buildResult()); }
    });
  }

  // Blacklist check (spec-exact: also checks MX IPs)
  private async checkBlacklists(aRecords: string[], mx: any) {
    const DNSBLS = [
      { name: 'Spamhaus ZEN', server: 'zen.spamhaus.org' },
      { name: 'Spamcop', server: 'bl.spamcop.net' },
      { name: 'SORBS', server: 'dnsbl.sorbs.net' },
      { name: 'Barracuda', server: 'b.barracudacentral.org' },
    ];
    const allIps = new Set<string>(aRecords.slice(0, 3));

    // Also resolve MX server IPs
    for (const mxHost of (mx.records || []).slice(0, 3)) {
      try {
        const mxIps = await dnsResolve(typeof mxHost === 'string' ? mxHost : '', 'A');
        mxIps.forEach((r: any) => allIps.add(r.data));
      } catch { /* ignore */ }
    }

    const ipsChecked: any[] = [];
    let listedCount = 0;

    for (const ip of allIps) {
      if (!ip || !ip.match(/^\d+\.\d+\.\d+\.\d+$/)) continue;
      const reversed = ip.split('.').reverse().join('.');
      const lists: any[] = [];
      let listed = false;

      for (const bl of DNSBLS) {
        try {
          const records = await dnsResolve(`${reversed}.${bl.server}`, 'A');
          if (records.length > 0) { listed = true; lists.push({ name: bl.name }); }
        } catch { /* not listed */ }
        await sleep(30);
      }

      ipsChecked.push({ ip, listed, lists, dnsbls_checked: DNSBLS.map(b => b.name) });
      if (listed) listedCount++;
    }

    const totalChecked = ipsChecked.length || 1;
    return {
      status: listedCount === 0 ? 'clean' : 'listed',
      checked: true,
      ips_checked: ipsChecked,
      total_ips: allIps.size,
      listed_ips_count: listedCount,
      clean_ips_count: ipsChecked.length - listedCount,
      reputation_score: Math.max(0, 100 - (listedCount * 15)),
    };
  }

  // Port scan via Shodan (optional)
  private async checkPorts(ip: string) {
    if (!ip || !config.shodan?.apiKey) {
      return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
    }
    try {
      const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${config.shodan.apiKey}`, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
      const data: any = await res.json();
      const HIGH_RISK = [21, 23, 25, 445, 3389, 3306, 5432, 27017];
      const openPorts = data.ports || [];
      const highRisk = openPorts.filter((p: number) => HIGH_RISK.includes(p));
      return { available: true, open_ports: openPorts, high_risk_ports: highRisk, high_risk_ports_count: highRisk.length };
    } catch {
      return { available: false, high_risk_ports: [], high_risk_ports_count: 0, open_ports: [] };
    }
  }

  // AbuseIPDB (optional, spec-exact)
  private async checkAbuseIPDB(ip: string) {
    if (!ip || !config.abuseipdb?.apiKey) {
      return { available: false, checked: false, configured: false, safe: true, abuse_confidence_score: 0, total_reports: 0 };
    }
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`, {
        headers: { 'Key': config.abuseipdb.apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return { available: false, checked: false, safe: true };
      const data: any = await res.json();
      const d = data.data || {};
      return {
        available: true, checked: true, configured: true,
        ip_address: ip, safe: (d.abuseConfidenceScore || 0) < 25,
        abuse_confidence_score: d.abuseConfidenceScore || 0,
        total_reports: d.totalReports || 0,
        num_distinct_users: d.numDistinctUsers || 0,
        country_name: d.countryName || 'Unknown',
        isp: d.isp || 'Unknown',
        usage_type: d.usageType || 'Unknown',
      };
    } catch {
      return { available: false, checked: false, safe: true };
    }
  }
}

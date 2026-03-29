import { prisma } from '../../config/database';
import { config } from '../../config/env';

const RELEVANT_KEYWORDS = [
  'windows','active directory','ldap','kerberos','ntlm','smb','rdp','exchange server','domain controller',
  'vmware','vsphere','esxi','vcenter','horizon',
  'cisco','ios xe','ios xr','asa','firepower','catalyst','nexus',
  'fortinet','fortigate','fortios','fortimanager','fortiweb','forticlient',
];

function isRelevant(desc: string, products: string[]): boolean {
  const text = (desc + ' ' + products.join(' ')).toLowerCase();
  return RELEVANT_KEYWORDS.some(kw => text.includes(kw));
}

function getSeverity(cvss: number | null): string {
  if (!cvss) return 'MEDIUM';
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function getTags(desc: string, products: string[]): string[] {
  const text = (desc + ' ' + products.join(' ')).toLowerCase();
  const tags: string[] = [];
  if (text.match(/windows|active directory|ldap|kerberos|rdp|smb/)) tags.push('Windows/AD');
  if (text.match(/vmware|vsphere|esxi|vcenter/)) tags.push('VMware');
  if (text.match(/cisco|ios xe|asa|firepower|catalyst/)) tags.push('Cisco');
  if (text.match(/fortinet|fortigate|fortios/)) tags.push('Fortinet');
  if (text.match(/remote code execution|rce/)) tags.push('RCE');
  if (text.match(/privilege escalation/)) tags.push('Privilege Escalation');
  if (text.match(/\bvpn\b|ssl vpn/)) tags.push('VPN');
  return tags;
}

async function aiAnalyze(cves: any[]): Promise<Map<string, {en: string; he: string; score: number}>> {
  const results = new Map();
  if (!config.llm?.apiKey || cves.length === 0) return results;

  const prompt = `You are a cybersecurity expert for an Israeli IT company managing Windows Server/AD, VMware, Cisco, and Fortinet infrastructure.

Analyze these CVEs and for each provide:
1. A 2-sentence explanation in English of why it matters to us
2. A 2-sentence explanation in Hebrew (עברית) of why it matters to us  
3. A relevance score 1-10 (10 = critical for our infrastructure)

CVEs:
${cves.map(c => `${c.id} (CVSS: ${c.cvss_score || 'N/A'}): ${(c.description || '').substring(0, 300)}`).join('\n\n')}

Respond ONLY with JSON array:
[{"id":"CVE-XXXX-XXXXX","en":"...","he":"...","score":8}, ...]`;

  try {
    const res = await fetch(`${config.llm.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${config.llm.apiKey}` },
      body: JSON.stringify({ model: config.llm.model || 'gpt-4o', max_tokens: 2000, messages: [{ role: 'user', content: prompt }] }),
      signal: AbortSignal.timeout(60000),
    });
    const data = await res.json() as any;
    const text = data.choices?.[0]?.message?.content || '[]';
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);
    for (const item of parsed) {
      results.set(item.id, { en: item.en, he: item.he, score: item.score });
    }
  } catch (err: any) {
    console.error('[CVE] AI analysis error:', err.message);
  }
  return results;
}

export class CveService {
  async fetchAndStore(): Promise<{ added: number; total: number }> {
    console.log('[CVE] Starting NVD fetch...');
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 2);

    const params = new URLSearchParams({
      pubStartDate: startDate.toISOString().replace('Z', '+00:00'),
      pubEndDate: endDate.toISOString().replace('Z', '+00:00'),
      resultsPerPage: '500',
      startIndex: '0',
    });

    const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, {
      headers: { 'User-Agent': 'MCS-Challenge-Scanner/1.0' },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`NVD API error: ${res.status}`);
    const data = await res.json() as any;
    const vulnerabilities = (data as any)?.vulnerabilities || [];

    const relevant: any[] = [];
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || cve.descriptions?.[0]?.value || 'No description available';
      let cvssScore: number | null = null;
      let cvssVector: string | null = null;
      const metrics = cve.metrics;
      if (metrics?.cvssMetricV31?.[0]) {
        cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore ?? null;
        cvssVector = metrics.cvssMetricV31[0].cvssData?.vectorString ?? null;
      } else if (metrics?.cvssMetricV30?.[0]) {
        cvssScore = metrics.cvssMetricV30[0].cvssData?.baseScore ?? null;
      } else if (metrics?.cvssMetricV2?.[0]) {
        cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore ?? null;
      }
      const products: string[] = [];
      for (const cfg of cve.configurations || []) {
        for (const node of cfg.nodes || []) {
          for (const match of node.cpeMatch || []) {
            const parts = (match.criteria || '').split(':');
            if (parts[3] && parts[4]) products.push(`${parts[3]} ${parts[4]}`);
          }
        }
      }
      if (!desc || !isRelevant(desc, products)) continue;
      const isExploited = (cve.cisaExploitAdd != null) ||
        (cve.references || []).some((r: any) => r.tags?.some((t: string) => t.toLowerCase().includes('exploit')));
      relevant.push({
        id: cve.id, published: cve.published, lastModified: cve.lastModified,
        desc, cvssScore, cvssVector, products: products.slice(0, 20),
        refs: (cve.references || []).slice(0, 5).map((r: any) => r.url),
        severity: getSeverity(cvssScore), tags: getTags(desc, products), isExploited,
      });
    }

    // AI analysis in batches of 5
    const aiMap = new Map();
    for (let i = 0; i < relevant.length; i += 5) {
      const batch = relevant.slice(i, i + 5);
      const batchResults = await aiAnalyze(batch);
      batchResults.forEach((v, k) => aiMap.set(k, v));
    }

    let added = 0;
    for (const c of relevant) {
      const ai = aiMap.get(c.id);
      try {
        await (prisma as any).$executeRaw`
          INSERT INTO cve_feed (id, published_at, last_modified, description, severity, cvss_score, cvss_vector, affected_products, "references", tags, is_exploited, ai_summary_en, ai_summary_he, ai_relevance_score)
          VALUES (${c.id}, ${new Date(c.published)}, ${new Date(c.lastModified)}, ${c.desc}, ${c.severity}, ${c.cvssScore}, ${c.cvssVector}, ${JSON.stringify(c.products)}::jsonb, ${JSON.stringify(c.refs)}::jsonb, ${JSON.stringify(c.tags)}::jsonb, ${c.isExploited}, ${ai?.en || null}, ${ai?.he || null}, ${ai?.score || 0})
          ON CONFLICT (id) DO UPDATE SET last_modified=EXCLUDED.last_modified, ai_summary_en=EXCLUDED.ai_summary_en, ai_summary_he=EXCLUDED.ai_summary_he, ai_relevance_score=EXCLUDED.ai_relevance_score
        `;
        added++;
      } catch {}
    }

    // Cleanup: delete older than 7 days
    await (prisma as any).$executeRaw`DELETE FROM cve_feed WHERE published_at < NOW() - INTERVAL '7 days'`;
    console.log(`[CVE] Done. ${added} relevant CVEs stored, old ones cleaned.`);
    return { added, total: vulnerabilities.length };
  }

  async getLatest(options: { severity?: string; lang?: string; limit?: number; offset?: number } = {}): Promise<any[]> {
    const { severity, limit = 50, offset = 0 } = options;
    if (severity) {
      return await (prisma as any).$queryRaw`SELECT * FROM cve_feed WHERE severity=${severity.toUpperCase()} ORDER BY ai_relevance_score DESC, published_at DESC LIMIT ${limit} OFFSET ${offset}`;
    }
    return await (prisma as any).$queryRaw`SELECT * FROM cve_feed ORDER BY ai_relevance_score DESC, published_at DESC LIMIT ${limit} OFFSET ${offset}`;
  }

  async getStats(): Promise<any> {
    const bySev = await (prisma as any).$queryRaw`SELECT severity, COUNT(*)::int as count, COUNT(*) FILTER (WHERE is_exploited=true)::int as exploited FROM cve_feed GROUP BY severity`;
    const total = await (prisma as any).$queryRaw`SELECT COUNT(*)::int as count FROM cve_feed`;
    const latest = await (prisma as any).$queryRaw`SELECT MAX(published_at) as last_updated FROM cve_feed`;
    return { total: (total as any[])[0]?.count || 0, bySeverity: bySev, lastUpdated: (latest as any[])[0]?.last_updated };
  }

  async sendDailyAlert(): Promise<void> {
    const since = new Date(); since.setHours(since.getHours() - 24);
    const important = await (prisma as any).$queryRaw`SELECT * FROM cve_feed WHERE (severity IN ('CRITICAL','HIGH') OR is_exploited=true) AND published_at > ${since} ORDER BY ai_relevance_score DESC, cvss_score DESC NULLS LAST LIMIT 15`;
    if ((important as any[]).length === 0) { console.log('[CVE] No important CVEs, skipping alert'); return; }

    const { EmailService } = await import('../email/emailService');
    const emailService = new EmailService();

    const sevColor: Record<string,string> = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#3b82f6' };
    const cards = (important as any[]).map((c: any) => `
      <div style="background:#111827;border-left:4px solid ${sevColor[c.severity]||'#3b82f6'};border-radius:8px;padding:16px;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
          <span style="color:#fff;font-weight:700;font-size:14px">${c.id}</span>
          <span style="background:${sevColor[c.severity]}20;color:${sevColor[c.severity]};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">${c.severity}</span>
          ${c.cvss_score ? `<span style="color:#64748b;font-size:11px">CVSS: ${c.cvss_score}</span>` : ''}
          ${c.is_exploited ? '<span style="background:#f9731620;color:#f97316;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">⚠️ EXPLOITED IN THE WILD</span>' : ''}
        </div>
        ${c.ai_summary_he ? `<div style="background:#0f1b2d;border-radius:6px;padding:10px;margin-bottom:8px"><div style="color:#60a5fa;font-size:10px;font-weight:700;margin-bottom:4px">🇮🇱 תובנה</div><p style="color:#e2e8f0;font-size:13px;line-height:1.5;direction:rtl">${c.ai_summary_he}</p></div>` : ''}
        ${c.ai_summary_en ? `<div style="background:#0f1b2d;border-radius:6px;padding:10px;margin-bottom:8px"><div style="color:#60a5fa;font-size:10px;font-weight:700;margin-bottom:4px">🔍 Insight</div><p style="color:#94a3b8;font-size:12px;line-height:1.5">${c.ai_summary_en}</p></div>` : ''}
        <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:8px">
          ${(c.tags||[]).map((t:string)=>`<span style="background:#1e3a5f;color:#60a5fa;padding:1px 6px;border-radius:4px;font-size:10px">${t}</span>`).join('')}
        </div>
        <a href="https://nvd.nist.gov/vuln/detail/${c.id}" style="color:#3b82f6;font-size:11px;text-decoration:none;display:block;margin-top:8px">🔗 NVD Details</a>
      </div>`).join('');

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
    <body style="background:#0c1220;color:#e2e8f0;font-family:Arial,sans-serif;padding:0;margin:0">
    <div style="max-width:680px;margin:0 auto;padding:40px 20px">
      <div style="text-align:center;margin-bottom:30px">
        <div style="color:#3b82f6;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">M-CHALLENGE SECURITY SCANNER</div>
        <h1 style="color:#fff;font-size:22px;margin:0 0 6px">🛡️ CVE Daily Intelligence Report</h1>
        <p style="color:#64748b;font-size:13px;margin:0">${(important as any[]).length} פגיעויות רלוונטיות חדשות • ${new Date().toLocaleDateString('he-IL')}</p>
      </div>
      ${cards}
      <div style="text-align:center;margin-top:30px;padding-top:20px;border-top:1px solid #1e2d40;color:#475569;font-size:11px">
        M-Challenge Security Scanner • Generated ${new Date().toISOString()} • Confidential
      </div>
    </div></body></html>`;

    await emailService.send('support@m-challenge.com', `🛡️ CVE Daily Report - ${(important as any[]).length} פגיעויות רלוונטיות - ${new Date().toLocaleDateString('he-IL')}`, html);
    await (prisma as any).$executeRaw`INSERT INTO cve_alert_log (cve_count, recipient, status) VALUES (${(important as any[]).length}, ${'support@m-challenge.com'}, ${'sent'})`;
    console.log('[CVE] Daily alert sent');
  }
}

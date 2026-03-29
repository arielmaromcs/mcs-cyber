/**
 * Shared utilities for scanner services.
 * DNS resolution via dns.google, safe HTTP fetching, domain extraction, etc.
 */

export interface DnsRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DnsResponse {
  Status: number;
  Answer?: DnsRecord[];
}

/**
 * Resolve DNS records via dns.google public API.
 */
export async function dnsResolve(name: string, type: string): Promise<DnsRecord[]> {
  try {
    // Try Google DNS over HTTPS first
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = (await res.json()) as DnsResponse;
      if (data.Answer && data.Answer.length > 0) return data.Answer;
    }
  } catch {}
  // Fallback to Node.js native DNS
  try {
    const dns = await import('dns');
    const { promisify } = await import('util');
    if (type === 'A') {
      const resolve4 = promisify(dns.resolve4);
      const ips = await resolve4(name);
      return ips.map((ip: string) => ({ name, type: 1, TTL: 300, data: ip }));
    } else if (type === 'AAAA') {
      const resolve6 = promisify(dns.resolve6);
      const ips = await resolve6(name);
      return ips.map((ip: string) => ({ name, type: 28, TTL: 300, data: ip }));
    } else if (type === 'MX') {
      const resolveMx = promisify(dns.resolveMx);
      const mxs = await resolveMx(name);
      return mxs.map((mx: any) => ({ name, type: 15, TTL: 300, data: `${mx.priority} ${mx.exchange}` }));
    } else if (type === 'TXT') {
      const resolveTxt = promisify(dns.resolveTxt);
      const txts = await resolveTxt(name);
      return txts.map((t: string[]) => ({ name, type: 16, TTL: 300, data: t.join('') }));
    } else if (type === 'NS') {
      const resolveNs = promisify(dns.resolveNs);
      const nss = await resolveNs(name);
      return nss.map((ns: string) => ({ name, type: 2, TTL: 300, data: ns }));
    }
  } catch {}
  return [];
}

/**
 * Safe HEAD request with timeout.
 */
export async function safeFetch(url: string, options: { method?: string; timeout?: number; followRedirect?: boolean } = {}): Promise<{ status: number; headers: Record<string, string>; ok: boolean; url: string } | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeout || 10000);
    const res = await fetch(url, {
      method: options.method || 'HEAD',
      redirect: options.followRedirect !== false ? 'follow' : 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, ok: res.ok, url: res.url };
  } catch {
    return null;
  }
}

/**
 * Safe GET with text response body.
 */
export async function safeGet(url: string, timeoutMs = 15000): Promise<{ status: number; headers: Record<string, string>; body: string; ok: boolean } | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { redirect: 'follow', signal: controller.signal });
    clearTimeout(timeout);
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, body, ok: res.ok };
  } catch {
    return null;
  }
}

/**
 * Extract domain from URL.
 */
export function extractDomain(url: string): string {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.hostname.replace(/^www\./, '');
  } catch {
    return url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

/**
 * Delay helper.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Run async tasks in parallel batches of `concurrency`.
 * Returns results in original order.
 */
export async function parallelBatch<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;

  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      try { results[i] = await fn(items[i]); } catch { results[i] = null as any; }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Count findings by severity.
 */
export function countBySeverity(findings: any[]): { critical: number; high: number; medium: number; low: number; info: number } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = (f.severity || 'info').toLowerCase() as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

/**
 * Calculate web security score using the weighted budget system from spec.
 * Now includes exposure penalties as separate budget.
 */
// Classify exposure into benign / review / critical
export function classifyExposure(exp: { path: string; confidence?: string; severity?: string; status_code?: number; source?: string }): 'benign' | 'review' | 'critical' {
  if (exp.confidence === 'confirmed' && (exp.severity === 'critical' || exp.severity === 'high')) return 'critical';
  const benignPatterns = [
    /^\/about/, /^\/contact/, /^\/blog/, /^\/sitemap/, /^\/rss/,
    /^\/terms/, /^\/accessibility/, /humans\.txt/, /security\.txt/,
    /^\/writers/, /^\/podcast/, /^\/archive/, /^\/magazine/,
    /^\/track/, /^\/independenceday/, /^\/rotteriframe/,
  ];
  if (benignPatterns.some(p => p.test(exp.path))) return 'benign';
  if (exp.source === 'js_analysis' && exp.severity === 'low') return 'benign';
  if (exp.status_code === 401 || exp.status_code === 403) return 'review';
  if (exp.path.includes('/api/') || exp.path.includes('/admin') || exp.path.includes('/dashboard')) return 'review';
  if (exp.confidence === 'weak' || !exp.confidence) return 'benign';
  return 'review';
}

export function calculateWebScore(
  counts: { critical: number; high: number; medium: number; low: number },
  exposureCounts?: { critical: number; high: number; medium: number; low: number },
  coverage?: { requestsMade: number; pagesScanned: number; totalFindings: number }
): { score: number; cap: number | null; capReason: string | null; penalties: Record<string, number>; breakdown: Record<string, any> } {
  const critPenalty = Math.min(counts.critical * 20, 60);
  const highPenalty = Math.min(counts.high * 10, 30);
  const medPenalty = Math.min(counts.medium * 5, 20);
  const lowPenalty = Math.min(counts.low * 2, 8);
  const ec = exposureCounts || { critical: 0, high: 0, medium: 0, low: 0 };
  const expCritPenalty = Math.min(ec.critical * 20, 40);
  const expHighPenalty = Math.min(ec.high * 8, 16);
  const totalPenalty = critPenalty + highPenalty + medPenalty + lowPenalty + expCritPenalty + expHighPenalty;
  let coveragePenalty = 0;
  if (coverage && coverage.requestsMade < 5 && coverage.pagesScanned < 1 && coverage.totalFindings === 0) {
    coveragePenalty = 15;
  }
  let score = Math.max(20, Math.min(100, 100 - totalPenalty - coveragePenalty));
  let cap: number | null = null;
  let capReason: string | null = null;
  if (ec.critical >= 2) { cap = 25; capReason = '2+ confirmed critical exposures'; }
  else if (ec.critical === 1) { cap = 40; capReason = 'Confirmed critical exposure'; }
  else if (counts.critical >= 2) { cap = 30; capReason = '2+ critical findings'; }
  else if (counts.critical === 1) { cap = 50; capReason = '1 critical finding'; }
  else if (counts.high >= 3) { cap = 60; capReason = '3+ high severity findings'; }
  if (cap !== null) score = Math.min(score, cap);
  return {
    score: Math.round(score), cap, capReason,
    penalties: { critical: critPenalty, high: highPenalty, medium: medPenalty, low: lowPenalty, exposure_critical: expCritPenalty, exposure_high: expHighPenalty, coverage: coveragePenalty },
    breakdown: { findings: counts, confirmedExposures: { critical: ec.critical, high: ec.high }, totalPenalty: Math.round(totalPenalty) },
  };
}

export function calculateRiskScore(webScore: number, dnsScore: number, emailScore: number = 0): number {
  return Math.max(0, Math.min(100, Math.round(webScore * 0.50 + dnsScore * 0.30 + (emailScore || webScore) * 0.20)));
}

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
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return [];
    const data = (await res.json()) as DnsResponse;
    return data.Answer || [];
  } catch {
    return [];
  }
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
 */
export function calculateWebScore(counts: { critical: number; high: number; medium: number; low: number }): { score: number; cap: number | null; capReason: string | null; penalties: Record<string, number> } {
  const critPenalty = Math.min(counts.critical * 15, 45);
  const highPenalty = Math.min(counts.high * 8, 25);
  const medPenalty = Math.min(counts.medium * 4, 20);
  const lowPenalty = Math.min(counts.low * 2, 10);
  let score = Math.max(0, Math.min(100, 100 - critPenalty - highPenalty - medPenalty - lowPenalty));

  let cap: number | null = null;
  let capReason: string | null = null;

  if (counts.critical >= 2) { cap = 25; capReason = '2+ critical findings'; }
  else if (counts.critical === 1) { cap = 45; capReason = '1 critical finding'; }
  else if (counts.high >= 2) { cap = 55; capReason = '2+ high severity findings'; }
  else if (counts.high === 1) { cap = 65; capReason = '1 high severity finding'; }

  if (cap !== null) score = Math.min(score, cap);

  return {
    score: Math.round(score),
    cap,
    capReason,
    penalties: { critical: critPenalty, high: highPenalty, medium: medPenalty, low: lowPenalty },
  };
}

/**
 * Calculate composite risk score: 60% web + 25% DNS + 15% email
 */
export function calculateRiskScore(webScore: number, dnsScore: number, emailScore: number = 0): number {
  return Math.round((100 - webScore) * 0.60 + (100 - dnsScore) * 0.25 + (100 - emailScore) * 0.15);
}

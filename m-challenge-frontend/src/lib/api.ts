const BASE = '/api';

function getToken(): string | null {
  return localStorage.getItem('mc_token');
}

export function setToken(token: string) {
  localStorage.setItem('mc_token', token);
}

export function clearToken() {
  localStorage.removeItem('mc_token');
}

async function request<T>(method: string, path: string, body?: any): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }

  return res.json();
}

export const api = {
  // Auth
  login: (email: string, password: string) => request<any>('POST', '/auth/login', { email, password }),
  register: (email: string, password: string, fullName?: string) => request<any>('POST', '/auth/register', { email, password, fullName }),
  whoami: () => request<any>('GET', '/auth/whoami'),

  // Web Scan
  startWebScan: (url: string, options?: any) => request<any>('POST', '/web-scan/start', { url, options, discover_subdomains: true, guest_scans_used: 0 }),
  webScanStatus: (id: string) => request<any>('GET', `/web-scan/status/${id}`),
  webScanResult: (id: string) => request<any>('GET', `/web-scan/result/${id}`),
  analyzeExploitability: (findings: any[]) => request<any>('POST', '/web-scan/analyze-exploitability', { findings }),

  // Email Scan
  startEmailScan: (domain: string) => request<any>('POST', '/email-scan/start', { domain }),
  emailScanStatus: (id: string) => request<any>('GET', `/email-scan/status/${id}`),
  emailScanResult: (id: string) => request<any>('GET', `/email-scan/result/${id}`),

  // Threat Intel
  startNmap: (target: string, config?: any) => request<any>('POST', '/threat-intel/start-nmap', { target, nmap_config: config }),
  nmapStart: (body: any) => request<any>('POST', '/threat-intel/nmap-start', body),
  nmapStatus: (jobId: string) => request<any>('GET', `/threat-intel/nmap-status/${jobId}`),
  nmapPortScan: (body: any) => request<any>('POST', '/threat-intel/nmap-port-scan', body),
  nmapExposure: (body: any) => request<any>('POST', '/threat-intel/run-nmap-exposure', body),

  // MITRE
  mitreCorrelate: (target: string, emailScan?: any, webScan?: any, threatIntel?: any) =>
    request<any>('POST', '/mitre/correlate', { target, email_scan: emailScan, web_scan: webScan, threat_intel: threatIntel }),
  executivePdf: (body: any) => request<any>('POST', '/mitre/executive-pdf', body),
  saveHistory: (body: any) => request<any>('POST', '/mitre/save-history', body),

  // Schedules
  createSchedule: (type: string, data: any) => request<any>('POST', '/schedules/create', { type, data }),
  deleteSchedule: (type: string, id: string) => request<any>('DELETE', `/schedules/${type}/${id}`),
  toggleSchedule: (type: string, id: string, status: boolean) => request<any>('PATCH', '/schedules/toggle', { type, schedule_id: id, current_status: status }),
  testSchedule: (scanType: string, target: string) => request<any>('POST', '/schedules/test', { scan_type: scanType, target }),
  tlsScan: (target: string) => request<any>('POST', '/tls-scan/scan', { target }),
  runScheduleNow: (type: string, scheduleId: string) => request<any>('POST', '/schedules/run-now/' + type + '/' + scheduleId, {}),
  getClients: () => request<any>('GET', '/clients'),
  createClient: (data: any) => request<any>('POST', '/clients', data),
  updateClient: (id: string, data: any) => request<any>('PATCH', '/clients/' + id, data),
  deleteClient: (id: string) => request<any>('DELETE', '/clients/' + id),
  listSchedules: () => request<any>('GET', '/schedules/list'),
  scheduleLogs: () => request<any>('GET', '/schedules/logs'),

  // Admin
  getUsers: () => request<any>('GET', '/admin/users'),
  inviteUser: (email: string, role: string, scans?: number) => request<any>('POST', '/admin/users/invite', { email, role, scans_remaining: scans }),
  updateUser: (id: string, data: any) => request<any>('PATCH', `/admin/users/${id}`, data),
  deleteUser: (id: string) => request<any>('DELETE', `/admin/users/${id}`),
  emailSettings: (action: string, provider?: string, settings?: any) => request<any>('POST', '/admin/email-settings', { action, provider, settings }),
  adminStats: () => request<any>('GET', '/admin/stats'),

  // Data
  latestScans: (target: string) => request<any>('POST', '/data/latest-scans', { target }),
  scanHistory: (target: string) => request<any>('GET', `/data/scan-history/${target}`),
  webScanHistory: () => request<any>('GET', '/web-scan/history'),
  emailScanHistory: () => request<any>('GET', '/email-scan/history'),
  getClientIp: () => request<any>('GET', '/threat-intel/client-ip'),
  upgrade: () => request<any>('POST', '/data/upgrade'),
  startFullScan: (data: any) => request<any>('POST', '/full-scan/run-now', data),
  getClientSchedules: (id: string) => request<any>('GET', '/clients/' + id + '/schedules'),

  // Nuclei
  nucleiScan: (data: any) => request<any>('POST', '/nuclei/scan', data),
  nucleiScans: () => request<any>('GET', '/nuclei/scans'),
  nucleiGetScan: (id: string) => request<any>('GET', '/nuclei/scan/' + id),
  nucleiDeleteScan: (id: string) => request<any>('DELETE', '/nuclei/scan/' + id),

  // PenTest
  pentestScan: (data: any) => request<any>('POST', '/pentest/scan', data),
  pentestReports: () => request<any>('GET', '/pentest/reports'),
  pentestGetReport: (id: string) => request<any>('GET', '/pentest/report/' + id),
  pentestDeleteReport: (id: string) => request<any>('DELETE', '/pentest/report/' + id),
  pentestHtmlUrl: (id: string) => '/api/pentest/report/' + id + '/html',
  createFullScanSchedule: (data: any) => request<any>('POST', '/full-scan/start', data),
};

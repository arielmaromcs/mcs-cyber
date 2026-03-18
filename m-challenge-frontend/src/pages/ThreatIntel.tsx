import { useLang } from '../hooks/useLang';
import { useState, useEffect, useRef, useCallback } from 'react';
import { Crosshair, Server, Shield, AlertTriangle, CheckCircle2, Loader2, ChevronDown, ExternalLink, Globe, Mail, Download } from "lucide-react";
import { generateThreatReport, downloadReport } from '../lib/reportGenerator';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { Card, Badge, Button, Spinner } from '../components/ui';

type Step = 'idle' | 'discovery' | 'profile' | 'scanning' | 'decision' | 'exposure' | 'results';

interface DnsResolution { all_ips: string[]; a_records: { ip: string }[]; mx_records: string[]; txt_records: string[]; ns_records: string[]; aaaa_records: string[]; mx_ips?: Record<string, string>; }
interface ServiceInfo { port: number; protocol: string; service: string; product: string; version: string; }
interface DiscoveryResult { open_ports: number[]; services: ServiceInfo[]; completed_at: string; }
interface ScanDecision { scanType: 'cve_only' | 'cve_nse'; selectedPorts: number[]; }
interface ExposureResult { cves: any[]; nse_findings: any[]; raw_output: string; completed_at: string; }

function parseServicesFromStdout(stdout: string): ServiceInfo[] {
  const services: ServiceInfo[] = [];
  for (const line of (stdout || '').split('\n')) {
    const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*$/);
    if (m) {
      services.push({ port: parseInt(m[1]), protocol: m[2], service: m[3], product: '', version: '' });
    } else {
      const m2 = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s+(.+)$/);
      if (m2) {
        const rest = (m2[4] || '').trim();
        const parts = rest.split(/\s+/);
        services.push({ port: parseInt(m2[1]), protocol: m2[2], service: m2[3], product: parts[0] || '', version: rest });
      }
    }
  }
  return services;
}

function extractCVEs(output: string): any[] {
  const matches = (output || '').match(/CVE-\d{4}-\d{4,}/g) || [];
  return [...new Set(matches)].map(cve => ({ cve, severity: 'high', evidence: 'Found in NSE output', recommendation: 'Update to latest version' }));
}

function parseNSEFindings(output: string): any[] {
  const findings: any[] = [];
  const lines = (output || '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('VULNERABLE') || lines[i].includes('State: VULNERABLE')) {
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 10));
      const cveMatch = context.join('\n').match(/(CVE-\d{4}-\d{4,})/);
      findings.push({ title: cveMatch ? 'Vulnerability: ' + cveMatch[1] : 'Potential vulnerability detected', severity: 'medium', evidence: context.join('\n'), recommendation: 'Review service configuration and update to latest version' });
    }
  }
  return findings;
}

function assessPortRisk(port: number): string {
  if ([22, 23, 3389, 5900, 445, 135, 139].includes(port)) return 'high';
  if ([80, 443, 8080, 8443, 21, 25, 110, 143, 993, 995, 587].includes(port)) return 'medium';
  return 'low';
}

function cleanTarget(input: string): string {
  return input.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

const PROFILES = [
  { id: 'baseline_syn_1000', label: 'Quick Exposure', desc: 'SYN scan on top 1000 ports', time: '~30 sec', needsApproval: false },
  { id: 'service_discovery', label: 'Service Discovery', desc: 'Service + version + OS detection', time: '~2-5 min', needsApproval: true },
  { id: 'security_posture', label: 'Security Posture', desc: 'Deep scan + NSE scripts + CVE mapping', time: '~5-15 min', needsApproval: true },
];

function ThreatDownloadBtn({ data, target }: { data: any; target: string }) {
  const { t } = useLang();
  if (!data) return null;
  return (
    <button onClick={() => downloadReport(generateThreatReport(data, target), `threat-scan-${target.replace(/[^a-z0-9]/gi,'-')}.html`)}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition">
      <Download size={13} /> {t("Download Report")}
    </button>
  );
}

export default function ThreatIntel() {
  const { t } = useLang();
  const { user } = useAuth();
  const [domain, setDomain] = useState('');

  // Auto-fill from URL param (from MITRE page)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const d = params.get('domain');
    if (d) setDomain(d);
  }, []);
  const [step, setStep] = useState<Step>('idle');
  const [error, setError] = useState('');
  const [dnsResolution, setDnsResolution] = useState<DnsResolution | null>(null);
  const [selectedIps, setSelectedIps] = useState<string[]>([]);
  const [hasPermission, setHasPermission] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState('baseline_syn_1000');
  const [deepScanAuthorized, setDeepScanAuthorized] = useState(false);
  const [discoveryResults, setDiscoveryResults] = useState<Record<string, DiscoveryResult>>({});
  const pollIntervalsRef = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  const [scanDecisions, setScanDecisions] = useState<Record<string, ScanDecision>>({});
  const [exposureResults, setExposureResults] = useState<Record<string, ExposureResult>>({});
  const exposurePollRef = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => { try { setHistory(JSON.parse(localStorage.getItem('nmap_scan_history') || '[]')); } catch {} }, []);
  useEffect(() => () => { Object.values(pollIntervalsRef.current).forEach(clearInterval); Object.values(exposurePollRef.current).forEach(clearInterval); }, []);

  const startDiscovery = async () => {
    const input = domain.trim();
    if (!input) return;
    setError(''); setStep('discovery');
    setDnsResolution(null); setSelectedIps([]); setHasPermission(false);
    setDiscoveryResults({}); setScanDecisions({}); setExposureResults({});
    try {
      if (IP_RE.test(input)) {
        setDnsResolution({ all_ips: [input], a_records: [{ ip: input }], mx_records: [], txt_records: [], ns_records: [], aaaa_records: [] });
        setSelectedIps([input]);
        setStep('profile');
      } else {
        const data = await api.startNmap(cleanTarget(input), { scan_a_records: true, scan_mx_records: true, profile: 'baseline_syn_1000', scan_all_discovered_ports: false, client_approved: false });
        const disc = data.discovery || {};
        const allIps = disc.ips || [];
        setDnsResolution({ all_ips: allIps, a_records: (disc.a_records || allIps).map((ip: string) => ({ ip })), mx_records: disc.mx_records || [], txt_records: disc.txt_records || [], ns_records: disc.ns_records || [], aaaa_records: disc.aaaa_records || [], mx_ips: disc.mx_ips || {} });
        setSelectedIps((disc.a_records || []).map((ip: string) => ip));
        if (data.jobs?.length) {
          for (const job of data.jobs) {
            if (job.job_id && job.status !== 'completed') startPollingDiscovery(job.ip, job.job_id);
            else if (job.open_ports?.length) setDiscoveryResults(prev => ({ ...prev, [job.ip]: { open_ports: job.open_ports.map((p: any) => p.port || p), services: job.open_ports, completed_at: new Date().toISOString() } }));
          }
        }
        setStep('profile');
      }
    } catch (e: any) { setError(e.message); setStep('idle'); }
  };

  const startScanning = async () => {
    if (!hasPermission) { setError('יש לאשר הרשאה לביצוע בדיקות'); return; }
    if (selectedIps.length === 0) return;
    if ((selectedProfile === 'service_discovery' || selectedProfile === 'security_posture') && !deepScanAuthorized) { setError('יש לאשר הרשאה לסריקות מתקדמות'); return; }
    setError(''); setStep('scanning'); setDiscoveryResults({});
    for (const ip of selectedIps) {
      const cleaned = cleanTarget(ip);
      try {
        const response = await api.nmapStart({ target: cleaned, profile: selectedProfile, client_approved: selectedProfile === 'baseline_syn_1000' ? true : deepScanAuthorized });
        if (response.ok && response.job_id) startPollingDiscovery(cleaned, response.job_id);
        else if (response.ok && response.open_ports) setDiscoveryResults(prev => ({ ...prev, [cleaned]: { open_ports: response.open_ports.map((p: any) => p.port), services: response.open_ports, completed_at: new Date().toISOString() } }));
      } catch (e: any) { setError('Scan failed for ' + ip + ': ' + e.message); }
    }
  };

  const startPollingDiscovery = useCallback((ip: string, jobId: string) => {
    let backoff = 5000;
    const poll = async () => {
      try {
        const data = await api.nmapStatus(jobId);
        if (data.status === 'completed' || data.status === 'done') {
          clearInterval(pollIntervalsRef.current[ip]); delete pollIntervalsRef.current[ip];
          const stdout = data.result?.stdout || data.stdout || '';
          const svcs = data.result?.open_ports || data.open_ports || parseServicesFromStdout(stdout);
          setDiscoveryResults(prev => ({ ...prev, [ip]: { open_ports: svcs.map((s: any) => s.port || s), services: svcs, completed_at: new Date().toISOString() } }));
        } else if (data.status === 'failed' || data.status === 'error') {
          clearInterval(pollIntervalsRef.current[ip]); delete pollIntervalsRef.current[ip];
          setError('Scan failed for ' + ip);
        }
      } catch (e: any) { if (e.message?.includes('429')) backoff = Math.min(backoff * 2, 40000); }
    };
    pollIntervalsRef.current[ip] = setInterval(poll, backoff);
    poll();
  }, []);

  useEffect(() => {
    if (step !== 'scanning') return;
    const pending = Object.keys(pollIntervalsRef.current).length;
    const completed = Object.keys(discoveryResults).length;
    if (pending === 0 && completed > 0 && completed >= selectedIps.length) {
      setStep('decision');
      const decisions: Record<string, ScanDecision> = {};
      for (const [ip, dr] of Object.entries(discoveryResults)) decisions[ip] = { scanType: 'cve_only', selectedPorts: dr.open_ports };
      setScanDecisions(decisions);
    }
  }, [step, discoveryResults, selectedIps.length]);

  const togglePort = (ip: string, port: number) => {
    setScanDecisions(prev => { const cur = prev[ip] || { scanType: 'cve_only', selectedPorts: [] }; const ports = cur.selectedPorts.includes(port) ? cur.selectedPorts.filter(p => p !== port) : [...cur.selectedPorts, port]; return { ...prev, [ip]: { ...cur, selectedPorts: ports } }; });
  };
  const setScanType = (ip: string, type: 'cve_only' | 'cve_nse') => { setScanDecisions(prev => ({ ...prev, [ip]: { ...prev[ip], scanType: type } })); };

  const startExposure = async (ip: string) => {
    const decision = scanDecisions[ip];
    if (!decision || decision.selectedPorts.length === 0) return;
    setStep('exposure'); setError('');
    try {
      const response = await api.nmapStart({ target: ip, profile: decision.scanType === 'cve_only' ? 'vuln' : 'smart_vuln', ports: decision.selectedPorts.join(','), client_approved: true, max_output: 200000 });
      if (response.ok && response.job_id) startPollingExposure(ip, response.job_id);
      else if (response.ok && (response.stdout || response.stage2)) processExposureResult(ip, response);
    } catch (e: any) { setError('Exposure scan failed: ' + e.message); }
  };

  const startAllExposure = async () => { setStep('exposure'); setError(''); for (const ip of Object.keys(scanDecisions)) await startExposure(ip); };

  const startPollingExposure = useCallback((ip: string, jobId: string) => {
    let backoff = 5000;
    const poll = async () => {
      try {
        const data = await api.nmapStatus(jobId);
        if (data.status === 'completed' || data.status === 'done') { clearInterval(exposurePollRef.current[ip]); delete exposurePollRef.current[ip]; processExposureResult(ip, data.result || data); }
        else if (data.status === 'failed' || data.status === 'error') { clearInterval(exposurePollRef.current[ip]); delete exposurePollRef.current[ip]; setError('Exposure failed for ' + ip); }
      } catch (e: any) { if (e.message?.includes('429')) backoff = Math.min(backoff * 2, 40000); }
    };
    exposurePollRef.current[ip] = setInterval(poll, backoff);
    poll();
  }, []);

  const processExposureResult = useCallback((ip: string, result: any) => {
    const rawOutput = result?.stage2?.stdout || result?.stdout || '';
    const cves = result?.vulnerabilities || extractCVEs(rawOutput);
    const nseFindings = parseNSEFindings(rawOutput);
    setExposureResults(prev => ({ ...prev, [ip]: { cves, nse_findings: nseFindings, raw_output: rawOutput, completed_at: new Date().toISOString() } }));
    const entry = { id: Date.now() + Math.random(), domain, ip, timestamp: new Date().toISOString(), discovery: discoveryResults[ip], decision: scanDecisions[ip], exposure: { cves, nse_findings: nseFindings } };
    setHistory(prev => { const updated = [...prev, entry].slice(-20); localStorage.setItem('nmap_scan_history', JSON.stringify(updated)); return updated; });
  }, [domain, discoveryResults, scanDecisions]);

  useEffect(() => {
    if (step !== 'exposure') return;
    const pending = Object.keys(exposurePollRef.current).length;
    const completed = Object.keys(exposureResults).length;
    if (pending === 0 && completed > 0 && completed >= Object.keys(scanDecisions).length) setStep('results');
  }, [step, exposureResults, scanDecisions]);

  const loadHistoryEntry = (entry: any) => {
    Object.values(pollIntervalsRef.current).forEach(clearInterval);
    Object.values(exposurePollRef.current).forEach(clearInterval);
    pollIntervalsRef.current = {}; exposurePollRef.current = {};
    setDomain(entry.domain || entry.ip || "");
    setError("");
    const ip = entry.ip || "";
    if (entry.discovery?.services?.length || entry.discovery?.open_ports?.length) {
      const svcs = entry.discovery.services || (entry.discovery.open_ports || []).map((p: any) => typeof p === "number" ? { port: p, protocol: "tcp", service: "unknown", product: "", version: "" } : p);
      setDiscoveryResults({ [ip]: { open_ports: svcs.map((s: any) => s.port || s), services: svcs, completed_at: entry.timestamp } });
    }
    if (entry.decision) setScanDecisions({ [ip]: entry.decision });
    if (entry.exposure) {
      setExposureResults({ [ip]: { cves: entry.exposure.cves || [], nse_findings: entry.exposure.nse_findings || [], raw_output: entry.exposure.raw_output || "", completed_at: entry.timestamp } });
      setStep("results");
    } else if (entry.discovery) {
      setStep("decision");
    }
  };

  const resetScan = () => {
    Object.values(pollIntervalsRef.current).forEach(clearInterval);
    Object.values(exposurePollRef.current).forEach(clearInterval);
    pollIntervalsRef.current = {}; exposurePollRef.current = {};
    setStep('idle'); setDnsResolution(null); setSelectedIps([]); setHasPermission(false);
    setDiscoveryResults({}); setScanDecisions({}); setExposureResults({}); setError(''); setDeepScanAuthorized(false);
  };

  const stepIdx = ['idle','discovery','profile','scanning','decision','exposure','results'].indexOf(step);

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Crosshair size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">{t("Threat Intelligence")}</h1><p className="text-sm text-blue-100/60">{t("Port scanning, CVE mapping & NSE vulnerability analysis")}</p></div>
          </div>
          <div className="flex gap-2">
            <input value={domain} onChange={e => setDomain(e.target.value)} placeholder={t("Enter domain or IP")} onKeyDown={e => e.key === 'Enter' && startDiscovery()}
              className="flex-1 px-4 py-3 bg-white/8 border border-white/15 rounded-xl text-white placeholder:text-white/30 outline-none text-sm font-mono" />
            <Button onClick={step === 'idle' || step === 'results' ? startDiscovery : resetScan} size="lg">
              {step === 'idle' || step === 'results' ? 'Resolve DNS & Show IPs' : 'New Scan'}
            </Button>
          </div>
          {error && <div className="mt-2 text-sm text-red-400">{error}</div>}
        </div>
      </div>

      <div className="max-w-[1100px] mx-auto px-4 py-6">

        {/* Explanation cards when idle */}
        {(step === "idle") && (
          <div className="max-w-[800px] mx-auto py-12 text-center">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🎯</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Network Discovery")}</h3>
                <p className="text-xs text-white/40">{t("Network Discovery desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🔫</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Port and Service Scanning")}</h3>
                <p className="text-xs text-white/40">{t("Port and Service Scanning desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🕵️</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Exposure Assessment")}</h3>
                <p className="text-xs text-white/40">{t("Exposure Assessment desc")}</p>
              </div>
            </div>
          </div>
        )}
        {step !== 'idle' && (
          <Card className="p-4 mb-5"><div className="flex gap-2">
            {['Discovery','Profile','Scanning','Decision','Exposure','Results'].map((label, i) => {
              const isDone = stepIdx > i + 1; const isActive = stepIdx === i + 1;
              return (<div key={label} className="flex-1 text-center">
                <div className={'h-1.5 rounded-full mb-1.5 transition-all ' + (isDone ? 'bg-emerald-500' : isActive ? 'bg-blue-500 animate-pulse' : 'bg-white/5')} />
                <div className={'text-[10px] font-medium ' + (isDone ? 'text-emerald-400' : isActive ? 'text-blue-400' : 'text-white/25')}>{label}</div>
              </div>);
            })}
          </div></Card>
        )}

        {dnsResolution && (step === 'profile' || step === 'discovery') && (
          <Card className="p-5 mb-4">
            <h3 className="text-sm font-semibold text-white mb-3">{t("Discovered Records for")} <span className="font-mono text-blue-400">{domain}</span></h3>
            {/* A Records */}
            {dnsResolution.a_records.length > 0 && (<div className="mb-3">
              <div className="text-[10px] text-blue-400 font-semibold uppercase tracking-wider mb-1.5 flex items-center gap-1"><Globe size={10} /> {t("A Records (IPv4)")}</div>
              <div className="space-y-1">{dnsResolution.a_records.map(r => (
                <label key={r.ip} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/5 hover:border-blue-500/30 cursor-pointer transition">
                  <input type="checkbox" checked={selectedIps.includes(r.ip)} onChange={() => setSelectedIps(prev => prev.includes(r.ip) ? prev.filter(x => x !== r.ip) : [...prev, r.ip])} className="w-4 h-4 rounded" />
                  <span className="font-mono text-xs text-blue-300">{r.ip}</span>
                  <span className="ml-auto text-[9px] bg-blue-500/15 text-blue-400 px-1.5 py-0.5 rounded font-semibold">A</span>
                </label>
              ))}</div>
            </div>)}

<label className="flex items-center gap-2 mt-3 px-3 py-2 rounded-lg border border-amber-500/20 bg-amber-500/5 cursor-pointer">
              <input type="checkbox" checked={hasPermission} onChange={e => setHasPermission(e.target.checked)} className="w-4 h-4 rounded" />
              <span className="text-xs text-amber-200">{t("Permission check")}</span>
            </label>
          </Card>
        )}

        {step === 'profile' && (
          <Card className="p-5 mb-4">
            <h3 className="text-sm font-semibold text-white mb-3">{t("Select Scan Profile")}</h3>
            <div className="grid grid-cols-3 gap-3 mb-4">{PROFILES.map((p, i) => (
              <button key={p.id} onClick={() => setSelectedProfile(p.id)}
                className={'p-4 rounded-xl border text-left transition ' + (selectedProfile === p.id ? 'border-blue-500/50 bg-blue-500/10' : 'border-white/10 bg-white/[0.02] hover:border-white/20')}>
                <div className="flex items-center gap-2 mb-2">
                  <div className={'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ' + (selectedProfile === p.id ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/40')}>{i + 1}</div>
                  <span className="text-sm font-semibold text-white">{p.label}</span>
                </div>
                <p className="text-[11px] text-white/40 mb-1">{p.desc}</p>
                <span className="text-[10px] text-white/25">{p.time}</span>
              </button>
            ))}</div>
            {(selectedProfile === 'service_discovery' || selectedProfile === 'security_posture') && (
              <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-rose-500/20 bg-rose-500/5 cursor-pointer mb-4">
                <input type="checkbox" checked={deepScanAuthorized} onChange={e => setDeepScanAuthorized(e.target.checked)} className="w-4 h-4 rounded" />
                <span className="text-xs text-rose-200">אני מאשר/ת ביצוע סריקות מתקדמות</span>
              </label>
            )}
            <Button onClick={startScanning} disabled={!hasPermission || selectedIps.length === 0} size="lg">{t("Start Scan")} ({selectedIps.length} {t("IPs")})</Button>
          </Card>
        )}

        {step === 'scanning' && (
          <Card className="p-5 mb-4">
            <div className="flex items-center gap-2 mb-3"><Loader2 size={16} className="text-blue-400 animate-spin" /><h3 className="text-sm font-semibold text-white">Scanning {selectedIps.length} target(s)...</h3></div>
            {selectedIps.map(ip => { const dr = discoveryResults[ip]; return (
              <div key={ip} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-white/[0.03] mb-1.5">
                <span className="font-mono text-xs text-blue-300 w-32">{ip}</span>
                {dr ? (<><CheckCircle2 size={14} className="text-emerald-400" /><span className="text-xs text-emerald-400">{dr.services.length} ports found</span></>) : (<><Spinner size={12} /><span className="text-xs text-white/30">Scanning... (polling every 5s)</span></>)}
              </div>
            ); })}
          </Card>
        )}

        {step === 'decision' && (<div className="space-y-4 mb-4">
          {Object.entries(discoveryResults).map(([ip, dr]) => (
            <Card key={ip} className="p-5">
              <h3 className="text-sm font-semibold text-white mb-1 font-mono">{ip}</h3>
              <p className="text-[10px] text-white/30 mb-3">{dr.services.length} open ports discovered</p>
              <div className="space-y-1 mb-4">{dr.services.map((svc: any) => {
                const port = svc.port || svc; const selected = scanDecisions[ip]?.selectedPorts?.includes(port); const risk = assessPortRisk(port);
                return (<label key={port} className={'flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition ' + (selected ? 'bg-blue-500/10 border border-blue-500/25' : 'bg-white/[0.02] border border-white/5 hover:border-white/15')}>
                  <input type="checkbox" checked={!!selected} onChange={() => togglePort(ip, port)} className="w-4 h-4 rounded" />
                  <span className="font-mono text-xs text-blue-300 w-16">{port}/tcp</span>
                  <span className="text-xs text-white">{svc.service || 'unknown'}</span>
                  <span className="text-xs text-white/30 flex-1">{svc.product} {svc.version}</span>
                  <span className={'text-[9px] font-semibold px-2 py-0.5 rounded-full ' + (risk === 'high' ? 'bg-rose-500/15 text-rose-400' : risk === 'medium' ? 'bg-amber-500/15 text-amber-400' : 'bg-emerald-500/15 text-emerald-400')}>{risk}</span>
                </label>);
              })}</div>
              <div className="flex gap-2 mb-4">{(['cve_only','cve_nse'] as const).map(type => (
                <button key={type} onClick={() => setScanType(ip, type)} className={'px-4 py-2 rounded-lg text-xs font-medium border transition ' + (scanDecisions[ip]?.scanType === type ? 'bg-blue-500/15 text-blue-300 border-blue-500/30' : 'bg-white/[0.02] text-white/40 border-white/10')}>
                  {type === 'cve_only' ? 'CVE Only' : 'CVE + NSE'}
                </button>
              ))}</div>
              <Button onClick={() => startExposure(ip)} disabled={(scanDecisions[ip]?.selectedPorts?.length || 0) === 0} size="sm">{t("Start CVE Scan")} ({scanDecisions[ip]?.selectedPorts?.length || 0} {t("ports")})</Button>
            </Card>
          ))}
          {Object.keys(scanDecisions).length > 1 && <Button onClick={startAllExposure} size="lg" className="w-full">Scan All IPs</Button>}
        </div>)}

        {step === 'exposure' && (
          <Card className="p-5 mb-4">
            <div className="flex items-center gap-2 mb-3"><Loader2 size={16} className="text-blue-400 animate-spin" /><h3 className="text-sm font-semibold text-white">Running CVE / NSE analysis...</h3></div>
            {Object.keys(scanDecisions).map(ip => { const er = exposureResults[ip]; return (
              <div key={ip} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-white/[0.03] mb-1.5">
                <span className="font-mono text-xs text-blue-300 w-32">{ip}</span>
                {er ? (<><CheckCircle2 size={14} className="text-emerald-400" /><span className="text-xs text-emerald-400">{er.cves.length} CVEs, {er.nse_findings.length} NSE findings</span></>) : (<><Spinner size={12} /><span className="text-xs text-white/30">Analyzing...</span></>)}
              </div>
            ); })}
          </Card>
        )}

        {step === 'results' && Object.entries(exposureResults).map(([ip, er]) => (
          <div key={ip} className="mb-6">
            <h3 className="text-sm font-semibold text-white mb-3 font-mono">{ip} — Results</h3>
            {er.cves.length === 0 && er.nse_findings.length === 0 && (
              <Card className="p-5 mb-3 border-emerald-500/20"><div className="flex items-center gap-2"><CheckCircle2 size={18} className="text-emerald-400" /><div><div className="text-sm font-semibold text-emerald-300">No known vulnerabilities found</div><div className="text-xs text-white/30">Scan completed successfully. No CVEs or NSE findings detected.</div></div></div></Card>
            )}
            {er.cves.length > 0 && (
              <Card className="p-5 mb-3 border-rose-500/20">
                <h4 className="text-xs font-semibold text-rose-300 mb-2">CVEs Found ({er.cves.length})</h4>
                <div className="space-y-2">{er.cves.map((c: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 px-3 py-2 rounded-lg bg-rose-500/5">
                    <Badge severity={c.severity}>{c.severity}</Badge>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2"><span className="font-mono text-xs text-rose-300">{c.cve}</span>
                        <a href={'https://nvd.nist.gov/vuln/detail/' + c.cve} target="_blank" rel="noopener" className="text-[10px] text-blue-400 flex items-center gap-0.5 hover:underline"><ExternalLink size={9} /> NVD</a>
                      </div>
                      <div className="text-[11px] text-white/40 mt-0.5">{c.evidence}</div>
                    </div>
                  </div>
                ))}</div>
              </Card>
            )}
            {er.nse_findings.length > 0 && (
              <Card className="p-5 mb-3 border-purple-500/20">
                <h4 className="text-xs font-semibold text-purple-300 mb-2">NSE Findings ({er.nse_findings.length})</h4>
                <div className="space-y-2">{er.nse_findings.map((f: any, i: number) => (
                  <div key={i} className="px-3 py-2 rounded-lg bg-purple-500/5">
                    <div className="text-xs text-purple-200 font-medium">{f.title}</div>
                    <pre className="text-[10px] text-white/25 mt-1 whitespace-pre-wrap max-h-24 overflow-y-auto">{f.evidence}</pre>
                  </div>
                ))}</div>
              </Card>
            )}
            {er.raw_output && (<details className="mb-3"><summary className="text-xs text-white/30 cursor-pointer hover:text-white/50">Raw NSE Output</summary><pre className="mt-2 p-3 rounded-lg bg-[#0a0e1a] text-emerald-400 text-[10px] font-mono max-h-64 overflow-auto whitespace-pre-wrap">{er.raw_output}</pre></details>)}
          </div>
        ))}
        {step === 'results' && <Button onClick={resetScan} variant="secondary" className="w-full">{t("New Scan")}</Button>}

        {step === 'idle' && history.length > 0 && (
          <Card className="p-4"><h3 className="text-sm font-semibold text-white mb-2">Scan History</h3>
            <div className="space-y-1">{history.slice(-10).reverse().map((h: any) => (
              <div key={h.id} onClick={() => loadHistoryEntry(h)} className="flex items-center gap-3 text-xs px-2 py-1.5 hover:bg-blue-500/10 rounded-md cursor-pointer group transition">
                <Server size={12} className="text-white/20" /><span className="text-white font-mono">{h.domain}</span><span className="text-white/30">{h.ip}</span><span className="text-white/15 ml-auto">{new Date(h.timestamp).toLocaleDateString()}</span>
              </div>
            ))}</div>
          </Card>
        )}
      </div>
    </div>
  );
}

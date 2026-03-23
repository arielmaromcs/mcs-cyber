import { useLang } from '../hooks/useLang';
import { useState, useEffect, useCallback } from 'react';
import { Target, Download, Loader2, Shield, AlertTriangle, ChevronRight, ChevronDown, Play, Mail, Globe, Crosshair, Search } from "lucide-react";
import { generateMitreReport, downloadReport } from '../lib/reportGenerator';
import { api } from '../lib/api';
import { Card, Badge, Button, Tabs, ProgressCircle, EmptyState, Spinner, scoreColor } from '../components/ui';

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access': '#fb7185', 'Execution': '#f97316', 'Persistence': '#fbbf24', 'Privilege Escalation': '#a78bfa',
  'Defense Evasion': '#8b5cf6', 'Credential Access': '#ec4899', 'Discovery': '#2d7aff', 'Lateral Movement': '#06b6d4',
  'Collection': '#14b8a6', 'Command and Control': '#64748b', 'Exfiltration': '#f43f5e', 'Impact': '#dc2626',
  'Reconnaissance': '#6366f1',
};

function MitreDownloadBtn({ data, target }: { data: any; target: string }) {
  const { t } = useLang();
  if (!data) return null;
  return (
    <button onClick={() => downloadReport(generateMitreReport(data, target), `mitre-report-${target.replace(/[^a-z0-9]/gi,'-')}.html`)}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition">
      <Download size={13} /> {t("Download Report")}
    </button>
  );
}

export default function Mitre() {
  const { t } = useLang();
  const [target, setTarget] = useState('');
  const [allDomains, setAllDomains] = useState<string[]>([]);
  const [showDomainPicker, setShowDomainPicker] = useState(false);
  const [scans, setScans] = useState<any>({});
  const [selectedEmail, setSelectedEmail] = useState<any>(null);
  const [selectedWeb, setSelectedWeb] = useState<any>(null);
  const [selectedThreat, setSelectedThreat] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [loadingScans, setLoadingScans] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('overview');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  // Auto-scan states
  const [autoScanType, setAutoScanType] = useState<string | null>(null);
  const [autoScanProgress, setAutoScanProgress] = useState(0);
  const [autoScanStage, setAutoScanStage] = useState('');
  // Threat Intel inline states
  const [threatMode, setThreatMode] = useState(false);
  const [threatStep, setThreatStep] = useState<'dns' | 'profile' | 'scanning' | 'done'>('dns');
  const [threatIps, setThreatIps] = useState<string[]>([]);
  const [threatScanId, setThreatScanId] = useState('');

  // Load all previously scanned domains
  useEffect(() => {
    const loadDomains = async () => {
      try {
        const [wh, eh] = await Promise.all([
          api.webScanHistory().catch(() => ({ scans: [] })),
          api.emailScanHistory().catch(() => ({ scans: [] })),
        ]);
        const domains = new Set<string>();
        (wh.scans || []).forEach((s: any) => s.domain && domains.add(s.domain));
        (eh.scans || []).forEach((s: any) => s.domain && domains.add(s.domain));
        // Also from localStorage NMAP
        try {
          const nmapHist = JSON.parse(localStorage.getItem('nmap_scan_history') || '[]');
          nmapHist.forEach((h: any) => h.domain && domains.add(h.domain));
        } catch {}
        setAllDomains([...domains].sort());
      } catch {}
    };
    loadDomains();
  }, []);

  const selectDomain = (d: string) => {
    setTarget(d);
    setShowDomainPicker(false);
    setResult(null);
    setScans({});
    // Auto-load scans
    setTimeout(() => loadScansFor(d), 100);
  };

  const loadScansFor = useCallback(async (domain: string) => {
    if (!domain.trim()) return;
    setLoadingScans(true); setError(''); setSelectedEmail(null); setSelectedWeb(null); setSelectedThreat(null);
    try {
      const data = await api.latestScans(domain.trim());
      // Also load localStorage NMAP scans
      try {
        const nmapHist = JSON.parse(localStorage.getItem('nmap_scan_history') || '[]');
        const matching = nmapHist.filter((h: any) => h.domain?.includes(domain.trim()) || h.ip?.includes(domain.trim()));
        if (matching.length > 0) {
          data.threat_scans = [...(data.threat_scans || []), ...matching.map((h: any) => ({ id: h.id, created_at: h.timestamp, summary: `NMAP: ${h.ip || h.domain}`, raw: h }))];
        }
      } catch {}
      setScans(data);
      if (data.email_scans?.[0]) setSelectedEmail(data.email_scans[0].raw || data.email_scans[0]);
      if (data.web_scans?.[0]) setSelectedWeb(data.web_scans[0].raw || data.web_scans[0]);
      if (data.threat_scans?.[0]) setSelectedThreat(data.threat_scans[0].raw || data.threat_scans[0]);
    } catch (e: any) { setError(e.message); }
    setLoadingScans(false);
  }, []);

  const loadScans = () => loadScansFor(target);

  // Auto-run missing scan
  const runMissingScan = async (type: 'email' | 'web') => {
    if (!target.trim()) return;
    setAutoScanType(type); setAutoScanProgress(0); setAutoScanStage('Starting...');
    try {
      if (type === 'email') {
        const { scan_id } = await api.startEmailScan(target.trim());
        const poll = setInterval(async () => {
          const s = await api.emailScanStatus(scan_id);
          setAutoScanProgress(s.progress || 0);
          setAutoScanStage(s.currentStage || s.current_stage || '');
          if (s.status === 'COMPLETED' || s.status === 'FAILED') {
            clearInterval(poll);
            setAutoScanType(null);
            if (s.status === 'COMPLETED') loadScansFor(target);
          }
        }, 2500);
      } else {
        const d = target.trim();
        const url = d.startsWith('http') ? d : `https://${d}`;
        const { scan_id } = await api.startWebScan(url, {});
        const poll = setInterval(async () => {
          const s = await api.webScanStatus(scan_id);
          setAutoScanProgress(s.progress || 0);
          setAutoScanStage(s.stage || '');
          if (s.status === 'COMPLETED' || s.status === 'FAILED') {
            clearInterval(poll);
            setAutoScanType(null);
            if (s.status === 'COMPLETED') loadScansFor(target);
          }
        }, 2500);
      }
    } catch (e: any) { setError(e.message); setAutoScanType(null); }
  };

  // Threat Intel inline flow
  const startThreatInline = async () => {
    setThreatMode(true); setThreatStep('dns'); setThreatIps([]);
    try {
      // Resolve IPs
      const res = await api.nmapStart({ target: target.trim(), profile: 'baseline_syn_1000', client_approved: true, sync: true });
      const ips = (res.open_ports || []).map((p: any) => p.port ? res.stdout?.match(/Nmap scan report for (\S+)/)?.[1] : '').filter(Boolean);
      // Get IPs from DNS
      const dnsIps = (res.open_ports || []).length > 0 ? [target.trim()] : [];
      setThreatIps(dnsIps);
      setThreatStep('scanning');
      // The baseline scan already ran, now save to localStorage and reload
      try {
        const hist = JSON.parse(localStorage.getItem('nmap_scan_history') || '[]');
        hist.push({ id: `nmap-${Date.now()}`, domain: target.trim(), ip: target.trim(), timestamp: new Date().toISOString(), discovery: { open_ports: res.open_ports, services: res.open_ports } });
        localStorage.setItem('nmap_scan_history', JSON.stringify(hist));
      } catch {}
      setThreatStep('done');
      setThreatMode(false);
      loadScansFor(target);
    } catch (e: any) {
      setError(e.message);
      setThreatMode(false);
    }
  };

  const runAnalysis = async () => {
    setLoading(true); setError(''); setResult(null);
    try {
      const data = await api.mitreCorrelate(target, selectedEmail, selectedWeb, selectedThreat);
      setResult(data); setTab('overview');
      if (data.attack_score) {
        try { await api.saveHistory({ target, attack_score: data.attack_score.score, risk_level: data.attack_score.rating?.toLowerCase() }); } catch {}
      }
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  const as = result?.attack_score;
  const hasEmail = (scans.email_scans || []).length > 0;
  const hasWeb = (scans.web_scans || []).length > 0;
  const hasThreat = (scans.threat_scans || []).length > 0;

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Target size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">{t("MITRE ATT&CK Analysis")}</h1><p className="text-sm text-blue-100/60">{t("Cross-vector attack surface correlation")}</p></div>
          </div>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input value={target} onChange={e => { setTarget(e.target.value); setShowDomainPicker(true); }}
                onFocus={() => setShowDomainPicker(true)}
                placeholder={t("Enter target domain or select from history")} style={{color:"#fff",caretColor:"#fff"}}
                className="w-full px-4 py-3 bg-white/8 border border-white/15 rounded-xl text-white placeholder:text-white/30 outline-none text-sm font-mono" />
              {/* Domain autocomplete dropdown */}
              {showDomainPicker && allDomains.length > 0 && (
                <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-mc-bg1 border border-mc-cardBorder rounded-xl shadow-xl max-h-[250px] overflow-y-auto">
                  <div className="px-3 py-2 text-[10px] text-mc-txt3 uppercase border-b border-mc-cardBorder">Previously Scanned Domains</div>
                  {allDomains.filter(d => !target || d.includes(target.toLowerCase())).map(d => (
                    <button key={d} onClick={() => selectDomain(d)}
                      className="w-full text-left px-3 py-2 text-sm text-white hover:bg-mc-brand/10 transition flex items-center gap-2 font-mono">
                      <Globe size={12} className="text-mc-brand/50" />{d}
                    </button>
                  ))}
                  {allDomains.filter(d => !target || d.includes(target.toLowerCase())).length === 0 && (
                    <div className="px-3 py-2 text-xs text-mc-txt3">No matching domains</div>
                  )}
                </div>
              )}
            </div>
            <Button onClick={loadScans} disabled={loadingScans || !target.trim()} variant="secondary" size="lg">
              {loadingScans ? <Spinner size={14} /> : <><Search size={14} /> Load Scans</>}
            </Button>
            <Button onClick={runAnalysis} disabled={loading || (!selectedEmail && !selectedWeb && !selectedThreat)} size="lg">
              {loading ? <><Spinner size={14} /> Analyzing...</> : 'Generate Analysis'}
            </Button>
          </div>
          {error && <div className="mt-2 text-sm text-mc-rose">{error}</div>}
        </div>
      </div>

      <div className="max-w-[1100px] mx-auto px-4 py-6" onClick={() => setShowDomainPicker(false)}>
        {/* Auto-scan progress bar */}
        {autoScanType && (
          <Card className="p-4 mb-4 animate-fadeIn">
            <div className="flex items-center gap-3 mb-2">
              <Loader2 size={16} className="text-mc-brand animate-spin" />
              <span className="text-sm text-white font-semibold">Running {autoScanType === 'email' ? 'Email' : 'Web'} Scan on {target}...</span>
              <span className="text-xs text-mc-txt3 ml-auto">{autoScanProgress}% — {autoScanStage}</span>
            </div>
            <div className="progress-track rounded-full h-1.5"><div className="progress-fill h-full rounded-full transition-all" style={{ width: `${autoScanProgress}%` }} /></div>
          </Card>
        )}

        {/* Threat Intel inline mode */}
        {threatMode && (
          <Card className="p-4 mb-4 animate-fadeIn">
            <div className="flex items-center gap-3 mb-2">
              <Loader2 size={16} className="text-purple-400 animate-spin" />
              <span className="text-sm text-white font-semibold">Running Threat Intelligence scan on {target}...</span>
              <span className="text-xs text-mc-txt3 ml-auto">{threatStep === 'dns' ? 'Resolving DNS...' : threatStep === 'scanning' ? 'Port scanning...' : 'Complete'}</span>
            </div>
            <div className="progress-track rounded-full h-1.5"><div className="progress-fill h-full rounded-full" style={{ width: threatStep === 'dns' ? '30%' : threatStep === 'scanning' ? '70%' : '100%' }} /></div>
          </Card>
        )}

        {/* Scan selection cards with "Run Scan" buttons */}
        {(
          <div className="grid grid-cols-3 gap-3 mb-5">
            {/* EMAIL */}
            <Card className={`p-3 ${hasEmail ? 'border-emerald-500/20' : 'border-rose-500/20'}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5"><Mail size={13} className="text-blue-400" /><span className="text-[10px] text-mc-txt3 uppercase font-semibold">Email Scan</span></div>
                {hasEmail && <span className="w-2 h-2 rounded-full bg-emerald-400" />}
              </div>
              {hasEmail ? (
                <select onChange={e => setSelectedEmail(scans.email_scans.find((i: any) => i.id === e.target.value)?.raw || scans.email_scans.find((i: any) => i.id === e.target.value))}
                  className="w-full bg-mc-bg2 text-xs text-white rounded p-1.5 outline-none border border-mc-cardBorder">
                  {scans.email_scans.map((i: any) => <option key={i.id} value={i.id}>{i.summary || `Email: ${i.email_security_score || '?'}`}</option>)}
                </select>
              ) : (
                <Button onClick={() => runMissingScan('email')} disabled={!!autoScanType || !target} size="sm" className="w-full mt-1">
                  <Play size={12} /> Run Email Scan
                </Button>
              )}
            </Card>

            {/* WEB */}
            <Card className={`p-3 ${hasWeb ? 'border-emerald-500/20' : 'border-rose-500/20'}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5"><Globe size={13} className="text-green-400" /><span className="text-[10px] text-mc-txt3 uppercase font-semibold">Web Scan</span></div>
                {hasWeb && <span className="w-2 h-2 rounded-full bg-emerald-400" />}
              </div>
              {hasWeb ? (
                <select onChange={e => setSelectedWeb(scans.web_scans.find((i: any) => i.id === e.target.value)?.raw || scans.web_scans.find((i: any) => i.id === e.target.value))}
                  className="w-full bg-mc-bg2 text-xs text-white rounded p-1.5 outline-none border border-mc-cardBorder">
                  {scans.web_scans.map((i: any) => <option key={i.id} value={i.id}>{i.summary || `Web: ${i.risk_score || '?'}`}</option>)}
                </select>
              ) : (
                <Button onClick={() => runMissingScan('web')} disabled={!!autoScanType || !target} size="sm" className="w-full mt-1">
                  <Play size={12} /> Run Web Scan
                </Button>
              )}
            </Card>

            {/* THREAT INTEL */}
            <Card className={`p-3 ${hasThreat ? 'border-emerald-500/20' : 'border-rose-500/20'}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5"><Crosshair size={13} className="text-purple-400" /><span className="text-[10px] text-mc-txt3 uppercase font-semibold">Threat Intel</span></div>
                {hasThreat && <span className="w-2 h-2 rounded-full bg-emerald-400" />}
              </div>
              {hasThreat ? (
                <select onChange={e => setSelectedThreat(scans.threat_scans.find((i: any) => i.id === e.target.value)?.raw || scans.threat_scans.find((i: any) => i.id === e.target.value))}
                  className="w-full bg-mc-bg2 text-xs text-white rounded p-1.5 outline-none border border-mc-cardBorder">
                  {scans.threat_scans.map((i: any) => <option key={i.id} value={i.id}>{i.summary || `NMAP: ${i.id?.slice(0,8)}`}</option>)}
                </select>
              ) : (
                <Button onClick={() => window.open("/threat?domain=" + encodeURIComponent(target), "_blank")} disabled={!target} size="sm" className="w-full mt-1" variant="secondary">
                  <Crosshair size={12} /> Run Threat Scan
                </Button>
              )}
            </Card>
          </div>
        )}

                {!result && !loading && (
          <div className="max-w-[800px] mx-auto py-8 text-center">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🗺️</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("MITRE ATT&CK Mapping")}</h3>
                <p className="text-xs text-white/40">{t("MITRE Mapping desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">⚔️</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Attacker Perspective")}</h3>
                <p className="text-xs text-white/40">{t("Attacker Perspective desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">📋</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Remediation Roadmap")}</h3>
                <p className="text-xs text-white/40">{t("Remediation Roadmap desc")}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && result.mitre_available !== false && (
          <div className="animate-fadeInUp">
            {as && (
              <Card glow className="p-6 mb-5 flex items-center gap-6">
                <ProgressCircle value={100 - as.score} size={80} stroke={5} />
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <div className="text-lg font-bold text-white">Attack Score: {as.score}/100</div>
                    <MitreDownloadBtn data={result} target={target} />
                  </div>
                  <div className="text-xs text-mc-txt3 mt-0.5">Rating: <span style={{ color: as.score >= 70 ? '#fb7185' : as.score >= 40 ? '#fbbf24' : '#34d399' }}>{as.rating}</span></div>
                  {as.reasoning && <div className="mt-2 space-y-0.5">{as.reasoning.map((r: string, i: number) => <div key={i} className="text-[11px] text-mc-txt2">• {r}</div>)}</div>}
                </div>
              </Card>
            )}

            <Tabs active={tab} onChange={setTab} tabs={[
              { key: 'overview', label: 'Overview' },
              { key: 'mitre', label: 'MITRE Mapping', count: result.mitre_mapping?.length },
              { key: 'findings', label: 'Priority Findings', count: result.priority_findings?.length },
              { key: 'roadmap', label: 'Remediation' },
              { key: 'attacker', label: 'Attacker View' },
            ]} />

            {tab === 'overview' && result.executive_summary && (
              <Card className="p-5 space-y-4">
                <div><h3 className="text-sm font-semibold text-white mb-1">Executive Summary</h3><p className="text-xs text-mc-txt2">{result.executive_summary.overview}</p></div>
                {result.executive_summary.key_risks?.length > 0 && (
                  <div><h4 className="text-xs font-semibold text-mc-rose mb-1">Key Risks</h4>{result.executive_summary.key_risks.map((r: string, i: number) => <div key={i} className="text-xs text-mc-txt2">• {r}</div>)}</div>
                )}
                {result.attack_surface_summary && (
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-mc-bg2 rounded-lg p-3"><div className="text-[10px] text-mc-txt3 mb-1">Posture</div><div className="text-sm font-semibold text-white">{result.attack_surface_summary.external_posture}</div></div>
                    <div className="bg-mc-bg2 rounded-lg p-3"><div className="text-[10px] text-mc-txt3 mb-1">Primary Vector</div><div className="text-sm font-semibold text-white">{result.attack_surface_summary.primary_exposure_vector}</div></div>
                    <div className="bg-mc-bg2 rounded-lg p-3"><div className="text-[10px] text-mc-txt3 mb-1">Confidence</div><div className="text-sm font-semibold text-mc-brand">{result.attack_surface_summary.confidence}</div></div>
                  </div>
                )}
              </Card>
            )}

            {tab === 'mitre' && (
              <div className="space-y-2">
                {(result.mitre_mapping || []).map((m: any, i: number) => (
                  <Card key={i} className="px-4 py-3 flex items-center gap-3">
                    <span className="w-2 h-8 rounded-full" style={{ background: TACTIC_COLORS[m.tactic] || '#64748b' }} />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-white">{m.technique}</div>
                      <div className="text-[10px] text-mc-txt3">{m.tactic} • {m.technique_id}</div>
                    </div>
                    <div className="text-[10px] text-mc-txt2 max-w-[300px] truncate">{m.why_relevant}</div>
                    <Badge severity={m.confidence === 'High' ? 'critical' : m.confidence === 'Medium' ? 'medium' : 'low'}>{m.confidence}</Badge>
                  </Card>
                ))}
              </div>
            )}

            {tab === 'findings' && (
              <div className="space-y-2">
                {(result.priority_findings || []).map((f: any, i: number) => (
                  <Card key={i} className="overflow-hidden">
                    <button onClick={() => setExpandedFinding(expandedFinding === `pf-${i}` ? null : `pf-${i}`)}
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-mc-bg2/50 transition">
                      <Badge severity={f.risk_level?.toLowerCase() || 'medium'}>{f.risk_level}</Badge>
                      <div className="flex-1"><div className="text-sm font-medium text-white">{f.issue}</div><div className="text-[10px] text-mc-txt3">{f.evidence_source}</div></div>
                      {expandedFinding === `pf-${i}` ? <ChevronDown size={14} className="text-mc-txt3" /> : <ChevronRight size={14} className="text-mc-txt3" />}
                    </button>
                    {expandedFinding === `pf-${i}` && (
                      <div className="px-4 pb-4 pt-1 border-t border-mc-cardBorder space-y-2 text-xs animate-fadeIn">
                        {f.technical_description && <p className="text-mc-txt2">{f.technical_description}</p>}
                        {f.business_impact && <div><span className="text-mc-txt3">Business Impact: </span><span className="text-mc-txt2">{f.business_impact}</span></div>}
                        {f.attack_scenario && <div><span className="text-mc-txt3">Attack Scenario: </span><span className="text-mc-txt2">{f.attack_scenario}</span></div>}
                        {f.remediation_steps?.length > 0 && (
                          <div><span className="text-mc-txt3">Remediation:</span>{f.remediation_steps.map((s: string, j: number) => <div key={j} className="text-mc-emerald ml-2">• {s}</div>)}</div>
                        )}
                      </div>
                    )}
                  </Card>
                ))}
              </div>
            )}

            {tab === 'roadmap' && result.remediation_roadmap && (
              <div className="space-y-4">
                {[{ key: 'immediate_30_days', label: '30 Days (Immediate)', color: 'text-mc-rose' },
                  { key: 'short_term_60_days', label: '60 Days (Short Term)', color: 'text-mc-amber' },
                  { key: 'long_term_90_days', label: '90 Days (Long Term)', color: 'text-mc-brand' }]
                  .map(({ key, label, color }) => (
                    <Card key={key} className="p-4">
                      <h3 className={`text-sm font-semibold ${color} mb-2`}>{label}</h3>
                      {(result.remediation_roadmap[key] || []).map((item: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-mc-txt2 py-0.5"><span className="text-mc-txt3">•</span>{item}</div>
                      ))}
                    </Card>
                  ))}
              </div>
            )}

            {tab === 'attacker' && result.attacker_view && (
              <div className="space-y-4">
                {/* Summary & Difficulty */}
                <Card className="p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-xl bg-rose-500/10 flex items-center justify-center"><span className="text-lg">&#9760;</span></div>
                    <div><div className="text-sm font-semibold text-white">{t("Attacker Perspective")}</div>
                    <div className="text-[10px] text-mc-txt3">Difficulty: <span className="text-mc-amber font-semibold">{result.attacker_view.difficulty_to_exploit}</span> &bull; Focus: <span className="text-mc-txt2">{typeof result.attacker_view.likely_focus === 'string' ? result.attacker_view.likely_focus : result.attacker_view.likely_focus?.join(', ')}</span></div></div>
                  </div>
                  <p className="text-xs text-mc-txt2 leading-relaxed">{result.attacker_view.summary}</p>
                </Card>

                {/* Detailed Scenario */}
                {result.attacker_view.detailed_scenario && (
                  <Card className="p-5">
                    <h3 className="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-2">Attack Scenario</h3>
                    <p className="text-xs text-mc-txt2 leading-relaxed whitespace-pre-line">{result.attacker_view.detailed_scenario}</p>
                  </Card>
                )}

                {/* What Attacker Sees */}
                {result.attacker_view.what_attacker_sees && result.attacker_view.what_attacker_sees.length > 0 && (
                  <Card className="p-5">
                    <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">What an Attacker Sees</h3>
                    <div className="space-y-1.5">{result.attacker_view.what_attacker_sees.map((item: string, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs"><span className="text-amber-400 mt-0.5">&#128065;</span><span className="text-mc-txt2">{item}</span></div>
                    ))}</div>
                  </Card>
                )}

                {/* Attack Narrative Steps */}
                {result.attacker_view.attack_narrative && result.attacker_view.attack_narrative.length > 0 && (
                  <Card className="p-5">
                    <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-3">Step-by-Step Attack Path</h3>
                    <div className="space-y-3">{result.attacker_view.attack_narrative.map((step: any, i: number) => (
                      <div key={i} className="flex gap-3">
                        <div className="w-7 h-7 rounded-full bg-red-500/15 flex items-center justify-center text-[11px] font-bold text-red-400 shrink-0">{step.step || i + 1}</div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-0.5"><span className="text-xs font-semibold text-white">{step.action}</span><span className="text-[10px] text-mc-txt3 font-mono">{step.technique}</span></div>
                          <p className="text-[11px] text-mc-txt2">{step.detail}</p>
                        </div>
                      </div>
                    ))}</div>
                  </Card>
                )}

                {/* First Steps */}
                {result.attacker_view.first_steps && (
                  <Card className="p-5">
                    <h3 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2">Attacker's First Moves</h3>
                    {(Array.isArray(result.attacker_view.first_steps) ? result.attacker_view.first_steps : [result.attacker_view.first_steps]).map((s: string, i: number) => (
                      <div key={i} className="text-xs text-mc-amber py-0.5">{String.fromCharCode(8594)} {s}</div>
                    ))}
                  </Card>
                )}

                {/* Risk Summary */}
                {result.attacker_view.risk_summary && (
                  <Card className="p-5 border-rose-500/20">
                    <h3 className="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-2">Risk Summary</h3>
                    <p className="text-xs text-mc-txt2 leading-relaxed">{result.attacker_view.risk_summary}</p>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {result?.mitre_available === false && (
          <Card className="p-6 text-center"><AlertTriangle size={24} className="text-mc-amber mx-auto mb-2" /><div className="text-sm text-mc-txt2">At least one scan required. Run missing scans above.</div></Card>
        )}
      </div>
    </div>
  );
}

import { useLang } from '../hooks/useLang';
import ScanHistory from '../components/ScanHistory';
import { useState, useEffect, useRef, useCallback } from 'react';
import { Globe, Search, Shield, ShieldCheck, ShieldAlert, Loader2, CheckCircle2, AlertCircle, ChevronDown, ChevronRight, ExternalLink, Bug, Download } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { generateWebReport, downloadReport } from '../lib/reportGenerator';
import { Card, Badge, ScoreDisplay, ProgressCircle, Tabs, Button, Input, scoreColor, scoreLabel, sevColor, EmptyState, Spinner } from '../components/ui';

const STAGES = ['DISCOVERY', 'INIT', 'TLS', 'DNS', 'HEADERS', 'COOKIES', 'EXPOSURE', 'CRAWL', 'CONTENT', 'FINALIZE'];

export default function WebScan() {
  const { t } = useLang();
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [riskCards, setRiskCards] = useState<any[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('findings');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval>>();

  // Load scan from history click or URL param
  const loadHistoryScan = useCallback((id: string) => {
    setScanId(id); setResult(null); setStatus(null); setRiskCards([]); setTab("findings");
    api.webScanResult(id).then((r: any) => {
      if (r.status === "COMPLETED") { setResult(r); setTab("findings"); }
    }).catch(() => {});
  }, []);

  // Check URL for ?scan=id on mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sid = params.get("scan");
    if (sid) loadHistoryScan(sid);
  }, [loadHistoryScan]);

  const guestCount = parseInt(localStorage.getItem('guest_scans_count') || '0');

  const startScan = async () => {
    if (!url.trim() || isStarting) return;
    setError('');
    setIsStarting(true);
    setResult(null);
    setRiskCards([]);

    try {
      const data = await api.startWebScan(url.trim(), { scan_profile: 'standard', max_pages: 50, max_depth: 3 });
      setScanId(data.scan_id);
      setTab('progress');

      if (!user) {
        localStorage.setItem('guest_scans_count', String(guestCount + 1));
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsStarting(false);
    }
  };

  // Polling
  useEffect(() => {
    if (!scanId) return;
    const poll = async () => {
      try {
        const s = await api.webScanStatus(scanId);
        setStatus(s);
        if (s.status === 'COMPLETED' || s.status === 'FAILED') {
          clearInterval(pollRef.current);
          if (s.status === 'COMPLETED') {
            const r = await api.webScanResult(scanId);
            setResult(r);
            setTab('findings');
            // Auto-run exploitability
            try {
              const ex = await api.analyzeExploitability(r.findings || []);
              setRiskCards(ex.risk_cards || []);
            } catch {}
          }
        }
      } catch {}
    };
    poll();
    pollRef.current = setInterval(poll, 1500);
    return () => clearInterval(pollRef.current);
  }, [scanId]);

  const isRunning = status && status.status === 'RUNNING';
  const isComplete = result?.status === 'COMPLETED';
  const stageIdx = STAGES.indexOf(status?.stage || 'INIT');
  const counts = result?.findingsCount || result?.findings_count || {};

  return (
    <div>
      {/* Hero Section */}
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Globe size={20} className="text-white" /></div>
            <div>
              <h1 className="text-2xl font-bold text-white">{t("Web Security Scanner")}</h1>
              <p className="text-sm text-blue-100/60">{t("Defensive reconnaissance & OWASP security audit")}</p>
            </div>
          </div>

          {/* URL Input */}
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && startScan()}
                placeholder={t("Enter URL placeholder")}
                className="w-full px-4 py-3 bg-white/8 border border-white/15 rounded-xl text-white placeholder:text-white/30 focus:border-mc-brand/50 focus:ring-2 focus:ring-mc-brand/20 outline-none text-sm font-mono" />
              <Search size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-white/25" />
            </div>
            <Button onClick={startScan} disabled={isStarting || !url.trim()} size="lg">
              {isStarting ? <><Spinner size={14} /> Scanning...</> : 'Start Scan'}
            </Button>
          </div>

          {!user && <div className="mt-2 text-[11px] text-blue-200/40">{5 - guestCount} free scans remaining</div>}
          {error && <div className="mt-2 text-sm text-mc-rose">{error}</div>}
        </div>
      </div>

      {/* Content */}
      <div className="max-w-[1100px] mx-auto px-4 py-6">
        {/* Progress */}
        {isRunning && status && (
          <Card className="p-5 mb-5 animate-fadeIn">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Loader2 size={16} className="text-mc-brand animate-spin" />
                <span className="text-sm font-semibold text-white">Scanning: {status.stage || 'Initializing'}</span>
              </div>
              <span className="text-xs text-mc-txt3 font-mono">{status.progress}%</span>
            </div>
            <div className="progress-track rounded-full h-1.5">
              <div className="progress-fill h-full rounded-full" style={{ width: `${status.progress}%` }} />
            </div>
            <div className="flex gap-1 mt-3">
              {STAGES.map((s, i) => (
                <div key={s} className={`flex-1 h-1 rounded-full ${i < stageIdx ? 'bg-mc-emerald' : i === stageIdx ? 'bg-mc-brand animate-pulse-slow' : 'bg-mc-bg2'}`} title={s} />
              ))}
            </div>
            <div className="flex justify-between mt-1 text-[9px] text-mc-txt3 font-mono">
              {STAGES.map(s => <span key={s}>{s.slice(0, 4)}</span>)}
            </div>
          </Card>
        )}

        {/* Results */}
        {isComplete && result && (
          <div className="animate-fadeInUp">
            {/* Score Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
              <Card glow className="p-4 text-center">
                <div className="text-[10px] text-mc-txt3 uppercase tracking-wider mb-2">Risk Score</div>
                <ProgressCircle value={100 - (result.riskScore || result.risk_score || 0)} size={56} />
                <div className="text-[10px] mt-1.5 font-medium" style={{ color: scoreColor(100 - (result.riskScore || 0)) }}>
                  {scoreLabel(100 - (result.riskScore || 0))}
                </div>
              </Card>
              <Card className="p-4 text-center">
                <div className="text-[10px] text-mc-txt3 uppercase tracking-wider mb-2">Web Security</div>
                <ScoreDisplay score={result.webSecurityScore || result.web_security_score || 0} size="sm" />
                <button onClick={() => downloadReport(generateWebReport(result, url), `web-scan-${url.replace(/[^a-z0-9]/gi,'-')}.html`)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition ml-auto">
                  <Download size={13} /> {t("Download Report")}
                </button>
              </Card>
              <Card className="p-4 text-center">
                <div className="text-[10px] text-mc-txt3 uppercase tracking-wider mb-2">DNS Security</div>
                <ScoreDisplay score={result.dnsSecurityScore || result.dns_security_score || 0} size="sm" />
              </Card>
              <Card className="p-4 text-center">
                <div className="text-[10px] text-mc-txt3 uppercase tracking-wider mb-2">Pages Scanned</div>
                <div className="text-2xl font-bold text-mc-brand font-mono">{result.pagesScanned || result.pages_scanned || 0}</div>
              </Card>
            </div>

            {/* Tabs */}
            <Tabs active={tab} onChange={setTab} tabs={[
              { key: 'findings', label: t('Findings'), count: (result.findings || []).length },
              { key: 'dns', label: 'DNS Security' },
              { key: 'exposure', label: 'Exposures', count: (result.exposureFindings || result.exposure_findings || []).length },
              { key: 'discovery', label: 'Discovery' },
              { key: 'exploit', label: 'Exploitability', count: riskCards.length },
            ]} />

            {/* Findings Tab */}
            {tab === 'findings' && (
              <div className="space-y-2">
                {(result.findings || []).length === 0 ? (
                  <EmptyState icon={ShieldCheck} title="No findings detected" subtitle="Scan completed with a clean report" />
                ) : (
                  (result.findings as any[]).map((f: any) => (
                    <Card key={f.id} className="overflow-hidden">
                      <button onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-mc-bg2/50 transition">
                        <Badge severity={f.severity}>{f.severity}</Badge>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-white truncate">{f.title}</div>
                          <div className="text-[11px] text-mc-txt3">{f.category} {f.owasp_category ? `• ${f.owasp_category}` : ''}</div>
                        </div>
                        {expandedFinding === f.id ? <ChevronDown size={14} className="text-mc-txt3" /> : <ChevronRight size={14} className="text-mc-txt3" />}
                      </button>
                      {expandedFinding === f.id && (
                        <div className="px-4 pb-4 pt-1 border-t border-mc-cardBorder space-y-2 animate-fadeIn">
                          <p className="text-xs text-mc-txt2">{f.description}</p>
                          {f.impact && <div className="text-xs"><span className="text-mc-txt3">Impact: </span><span className="text-mc-txt2">{f.impact}</span></div>}
                          {f.recommendation && <div className="text-xs"><span className="text-mc-txt3">Fix: </span><span className="text-mc-emerald">{f.recommendation}</span></div>}
                          {f.evidence && typeof f.evidence === 'object' && (
                            <pre className="text-[10px] bg-mc-bg2 rounded-lg p-2 text-mc-txt3 font-mono overflow-x-auto">{JSON.stringify(f.evidence, null, 2)}</pre>
                          )}
                        </div>
                      )}
                    </Card>
                  ))
                )}
              </div>
            )}

            {/* DNS Tab */}
            {tab === 'dns' && result.dnsAnalysis && (
              <Card className="p-4">
                <h3 className="text-sm font-semibold text-white mb-3">DNS Analysis</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  {['config_score', 'email_dns_score', 'takeover_risk_score', 'hygiene_score'].map(k => (
                    <div key={k} className="bg-mc-bg2 rounded-lg p-3 text-center">
                      <div className="text-[10px] text-mc-txt3 uppercase mb-1">{k.replace(/_/g, ' ')}</div>
                      <div className="text-lg font-bold font-mono" style={{ color: scoreColor(result.dnsAnalysis[k] || 0) }}>
                        {result.dnsAnalysis[k] || 0}
                      </div>
                    </div>
                  ))}
                </div>
                {result.dnsAnalysis.records && Object.entries(result.dnsAnalysis.records).map(([type, recs]: any) => (
                  recs?.length > 0 && (
                    <div key={type} className="mb-2">
                      <div className="text-[10px] text-mc-brand font-mono uppercase mb-1">{type}</div>
                      {recs.map((r: string, i: number) => <div key={i} className="text-xs text-mc-txt2 font-mono truncate">{r}</div>)}
                    </div>
                  )
                ))}
              </Card>
            )}

            {/* Exposure Tab */}
            {tab === 'exposure' && (
              <div className="space-y-2">
                {(result.exposureFindings || result.exposure_findings || []).map((e: any, i: number) => (
                  <Card key={i} className="px-4 py-3 flex items-center gap-3">
                    <Badge severity={e.severity}>{e.severity}</Badge>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono text-white truncate">{e.path}</div>
                      <div className="text-[10px] text-mc-txt3">HTTP {e.status_code} • {e.source}</div>
                    </div>
                    {e.accessible && <span className="text-[9px] bg-mc-rose/10 text-mc-rose px-1.5 py-0.5 rounded-full font-medium">Accessible</span>}
                  </Card>
                ))}
                {(result.exposureFindings || []).length === 0 && <EmptyState icon={ShieldCheck} title="No exposures detected" />}
              </div>
            )}

            {/* Discovery Tab */}
            {tab === 'discovery' && (
              <Card className="p-4">
                <h3 className="text-sm font-semibold text-white mb-3">Discovery Results</h3>
                {result.discovery?.hosts_discovered?.length > 0 ? (
                  <div className="space-y-1">
                    {result.discovery.hosts_discovered.map((h: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs px-2 py-1.5 rounded-md hover:bg-mc-bg2">
                        <span className={`w-1.5 h-1.5 rounded-full ${h.resolved ? 'bg-mc-emerald' : 'bg-mc-txt3'}`} />
                        <span className="text-mc-txt font-mono flex-1">{h.host}</span>
                        <span className="text-[9px] text-mc-txt3 bg-mc-bg2 px-1.5 py-0.5 rounded">{h.source}</span>
                      </div>
                    ))}
                  </div>
                ) : <EmptyState title="No hosts discovered" subtitle="Try enabling subdomain discovery" />}
              </Card>
            )}

            {/* Exploitability Tab */}
            {tab === 'exploit' && (
              <div className="space-y-2">
                {riskCards.map((c: any, i: number) => (
                  <Card key={i} className="p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge severity={c.severity}>{c.severity}</Badge>
                      <span className="text-sm font-semibold text-white">{c.title}</span>
                    </div>
                    <p className="text-xs text-mc-txt2 mb-2">{c.description}</p>
                    <div className="flex gap-4 text-[10px] text-mc-txt3">
                      <span>Difficulty: <span className="text-mc-txt2">{c.exploitation_difficulty}</span></span>
                      <span>Priority: <span className="text-mc-brand">#{c.remediation_priority}</span></span>
                    </div>
                  </Card>
                ))}
                {riskCards.length === 0 && <EmptyState icon={Bug} title="No exploitability data" subtitle="Analysis will run automatically when scan completes" />}
              </div>
            )}
          </div>
        )}
                {!scanId && !result && (
          <div className="max-w-[800px] mx-auto px-4 py-12 text-center">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🔍</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("OWASP Security Audit")}</h3>
                <p className="text-xs text-white/40">{t("OWASP Security Audit desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🛡️</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Headers & TLS Analysis")}</h3>
                <p className="text-xs text-white/40">{t("Headers TLS desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">📊</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Risk Scoring & Reports")}</h3>
                <p className="text-xs text-white/40">{t("Risk Scoring desc")}</p>
              </div>
            </div>
          </div>
        )}

        {!scanId && <ScanHistory type="web" onSelectScan={loadHistoryScan} />}
      </div>
    </div>
  );
}

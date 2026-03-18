import { useState } from 'react';
import { Globe, Play, Search, Loader2, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react';
import { api } from '../lib/api';
import { usePolling } from '../hooks/usePolling';
import { PageHeader, Card, CardGlow, Badge, Tabs, Input, Button, ProgressCircle, Tag, scoreColor } from '../components/ui';

export default function WebScanPage() {
  const [url, setUrl] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [tab, setTab] = useState('findings');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState('');

  const status = usePolling(
    () => api.webScanStatus(scanId!),
    1500,
    scanning && !!scanId,
    (data) => {
      setScanning(false);
      if (data.status === 'COMPLETED') api.webScanResult(scanId!).then(setResult);
    }
  );

  const start = async () => {
    if (!url.trim()) return;
    setError(''); setResult(null); setScanning(true);
    try {
      const r = await api.startWebScan(url.trim());
      setScanId(r.scan_id);
    } catch (e: any) { setError(e.message); setScanning(false); }
  };

  const findings = result?.findings || [];
  const fc = result?.findingsCount || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const stages = ['DISCOVERY', 'INIT', 'TLS', 'DNS', 'HEADERS', 'COOKIES', 'EXPOSURE', 'CRAWL', 'CONTENT', 'FINALIZE'];

  return (
    <div className="flex flex-col gap-4 animate-fade-in">
      <PageHeader icon={<Globe size={18} className="text-mc-brand" />} title="Web Security Scanner" subtitle="External attack surface analysis" />

      <CardGlow>
        <div className="flex gap-2.5">
          <div className="flex-1 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mc-txt3" />
            <Input value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && start()}
              placeholder="Enter URL (e.g. example.com)" className="pl-9" />
          </div>
          <Button onClick={start} disabled={!url.trim() || scanning}>
            {scanning ? <Loader2 size={14} className="animate-spin-slow" /> : <Play size={14} />}
            {scanning ? 'Scanning...' : 'Start Scan'}
          </Button>
        </div>
        {error && <p className="text-rose-400 text-xs mt-2">{error}</p>}
      </CardGlow>

      {scanning && status && (
        <Card className="text-center py-7">
          <ProgressCircle progress={status.progress || 0} status="running" />
          <div className="text-sm font-semibold text-mc-txt2 mt-3">{status.stage || 'Starting...'}</div>
          <div className="text-xs text-mc-txt3 mt-1">Stage {stages.indexOf(status.stage) + 1} / {stages.length}</div>
          <div className="flex justify-center gap-1 mt-3 flex-wrap">
            {stages.map((s, i) => {
              const si = stages.indexOf(status.stage);
              return <span key={s} className={`text-[7px] px-1.5 py-0.5 rounded ${i < si ? 'bg-emerald-400/10 text-emerald-400' : i === si ? 'bg-mc-brand/10 text-mc-brand animate-pulse-slow font-bold' : 'bg-mc-bg3 text-mc-txt3'}`}>{s}</span>;
            })}
          </div>
        </Card>
      )}

      {result && (
        <>
          <div className="grid grid-cols-4 gap-3">
            <Card className="text-center"><div className="text-[10px] text-mc-txt3">Web Score</div><div className={`font-mono font-bold text-2xl ${scoreColor(result.webSecurityScore)}`}>{result.webSecurityScore}</div></Card>
            <Card className="text-center"><div className="text-[10px] text-mc-txt3">DNS Score</div><div className={`font-mono font-bold text-2xl ${scoreColor(result.dnsSecurityScore)}`}>{result.dnsSecurityScore}</div></Card>
            <Card className="text-center"><div className="text-[10px] text-mc-txt3">Risk</div><div className={`font-mono font-bold text-2xl ${scoreColor(100 - result.riskScore)}`}>{result.riskScore}</div></Card>
            <Card className="text-center"><div className="text-[10px] text-mc-txt3">Pages</div><div className="font-mono font-bold text-xl text-white">{result.pagesScanned}</div><div className="text-[10px] text-mc-txt3">{result.scanDurationSeconds}s</div></Card>
          </div>

          <div className="flex gap-1.5 flex-wrap">
            {Object.entries(fc).filter(([, c]) => (c as number) > 0).map(([s, c]) => <Badge key={s} severity={s}>{s} ({c as number})</Badge>)}
          </div>

          <Tabs tabs={[{ id: 'findings', label: 'Findings', count: findings.length }, { id: 'dns', label: 'DNS' }, { id: 'exposures', label: 'Exposures', count: result.exposuresFound }]} active={tab} onChange={setTab} />

          {tab === 'findings' && (
            <div className="flex flex-col gap-1.5">
              {findings.map((f: any) => (
                <Card key={f.id} className="!p-0">
                  <button onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                    className="flex items-start gap-2.5 w-full p-3 text-left">
                    <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${f.severity === 'critical' ? 'bg-rose-500' : f.severity === 'high' ? 'bg-orange-500' : f.severity === 'medium' ? 'bg-amber-400' : 'bg-blue-400'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-semibold">{f.title}</span>
                        <Badge severity={f.severity} />
                        <Tag>{f.category}</Tag>
                      </div>
                      <div className="text-[11px] text-mc-txt3 mt-1 truncate">{f.description}</div>
                    </div>
                    {expanded === f.id ? <ChevronUp size={13} className="text-mc-txt3" /> : <ChevronDown size={13} className="text-mc-txt3" />}
                  </button>
                  {expanded === f.id && (
                    <div className="px-3 pb-3 border-t border-mc-bg3 pt-2.5 space-y-2">
                      {f.impact && <div><div className="text-[8px] text-mc-txt3 uppercase">Impact</div><div className="text-[11px] text-mc-txt2">{f.impact}</div></div>}
                      {f.recommendation && <div><div className="text-[8px] text-mc-txt3 uppercase">Recommendation</div><div className="text-[11px] text-emerald-400">{f.recommendation}</div></div>}
                      {f.owasp_category && <div className="text-[10px] text-mc-txt3">OWASP: {f.owasp_category}</div>}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}

          {tab === 'dns' && result.dnsAnalysis && (
            <Card>
              {Object.entries(result.dnsAnalysis.records || {}).map(([type, records]: [string, any]) => (
                <div key={type} className="mb-3">
                  <div className="text-[9px] text-mc-txt3 uppercase font-mono">{type}</div>
                  <div className="text-[11px] text-mc-txt2 font-mono bg-mc-bg1 rounded px-2.5 py-1.5 mt-1">{Array.isArray(records) ? records.join(', ') : String(records)}</div>
                </div>
              ))}
              {!result.dnsAnalysis.dnssec?.enabled && (
                <div className="flex items-center gap-2 text-amber-400 text-xs mt-3"><AlertTriangle size={13} />DNSSEC not enabled</div>
              )}
            </Card>
          )}

          {tab === 'exposures' && (
            <div className="flex flex-col gap-1.5">
              {(result.exposureFindings || []).map((e: any, i: number) => (
                <Card key={i} className="!border-l-2" style={{ borderLeftColor: e.severity === 'critical' ? '#f43f5e' : e.severity === 'medium' ? '#eab308' : '#64748b' }}>
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-xs">{e.path}</code>
                        <Badge severity={e.severity} />
                        <span className={`font-mono text-[10px] ${e.accessible ? 'text-emerald-400' : 'text-mc-txt3'}`}>{e.status_code}</span>
                      </div>
                      <div className="text-[10px] text-mc-txt3 mt-1">{e.exposure || e.risk_summary}</div>
                    </div>
                    <Tag>{e.source}</Tag>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

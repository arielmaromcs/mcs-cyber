import { useState } from 'react';
import { Mail, Play, Loader2, CheckCircle2 } from 'lucide-react';
import { api } from '../lib/api';
import { usePolling } from '../hooks/usePolling';
import { PageHeader, Card, CardGlow, Tabs, Input, Button, ProgressCircle, scoreColor } from '../components/ui';

export default function EmailScanPage() {
  const [domain, setDomain] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [tab, setTab] = useState('score');
  const [error, setError] = useState('');

  const status = usePolling(() => api.emailScanStatus(scanId!), 3000, scanning && !!scanId, (data) => {
    setScanning(false);
    if (data.status === 'COMPLETED') api.emailScanResult(scanId!).then(setResult);
  });

  const start = async () => {
    if (!domain.trim()) return;
    setError(''); setResult(null); setScanning(true);
    try { const r = await api.startEmailScan(domain.trim()); setScanId(r.scan_id); }
    catch (e: any) { setError(e.message); setScanning(false); }
  };

  const stages = ['DNS', 'SPF', 'DKIM', 'DMARC', 'MX', 'WHOIS', 'SMTP', 'Blacklist', 'Ports', 'AbuseIPDB'];
  const sb = result?.scoreBreakdown || {};

  return (
    <div className="flex flex-col gap-4 animate-fade-in">
      <PageHeader icon={<Mail size={18} className="text-mc-brand" />} title="Email Security Scanner" subtitle="SPF · DKIM · DMARC · Blacklist · AbuseIPDB" />
      <CardGlow>
        <div className="flex gap-2.5">
          <Input value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && start()} placeholder="Enter domain" className="flex-1" />
          <Button onClick={start} disabled={!domain.trim() || scanning}>
            {scanning ? <Loader2 size={14} className="animate-spin-slow" /> : <Play size={14} />}
            {scanning ? 'Scanning...' : 'Scan'}
          </Button>
        </div>
        {error && <p className="text-rose-400 text-xs mt-2">{error}</p>}
      </CardGlow>

      {scanning && status && (
        <Card className="text-center py-7">
          <ProgressCircle progress={status.progress || 0} />
          <div className="text-sm font-semibold text-mc-txt2 mt-3">{status.currentStage}</div>
          <div className="h-1 bg-mc-bg3 rounded mt-4 overflow-hidden"><div className="h-full bg-mc-brand rounded transition-all" style={{ width: `${status.progress}%` }} /></div>
        </Card>
      )}

      {result && (
        <>
          <Card className="text-center py-5">
            <div className={`font-mono font-bold text-4xl ${scoreColor(result.emailSecurityScore)}`}>{result.emailSecurityScore}</div>
            <div className={`text-[11px] font-semibold mt-1 ${scoreColor(result.emailSecurityScore)}`}>{result.scoreRating}</div>
          </Card>

          <Tabs tabs={[{ id: 'score', label: 'Score' }, { id: 'recs', label: 'Recommendations' }]} active={tab} onChange={setTab} />

          {tab === 'score' && (
            <div className="flex flex-col gap-2">
              {[['SPF', sb.spf, 18], ['DKIM', sb.dkim, 18], ['DMARC', sb.dmarc, 22], ['Relay', sb.relay, 18], ['Infrastructure', sb.misc, 12], ['Ports', sb.ports, 12]].map(([n, s, mx]) => (
                <Card key={n as string}>
                  <div className="flex justify-between mb-1.5">
                    <span className="text-xs font-semibold text-mc-txt2">{n}</span>
                    <span className={`font-mono text-xs font-bold ${scoreColor(((s as number) / (mx as number)) * 100)}`}>{s}/{mx}</span>
                  </div>
                  <div className="h-1 bg-mc-bg3 rounded overflow-hidden">
                    <div className="h-full rounded transition-all duration-700" style={{ width: `${((s as number) / (mx as number)) * 100}%`, background: (s as number) / (mx as number) >= 0.8 ? '#34d399' : (s as number) / (mx as number) >= 0.5 ? '#3b8bff' : '#fbbf24' }} />
                  </div>
                </Card>
              ))}
            </div>
          )}

          {tab === 'recs' && (
            <Card>
              {(result.recommendations || []).map((r: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-[11px] text-mc-txt2 py-1">
                  <CheckCircle2 size={12} className="text-emerald-400 mt-0.5 shrink-0" />{r}
                </div>
              ))}
            </Card>
          )}
        </>
      )}
    </div>
  );
}

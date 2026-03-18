import { useState } from 'react';
import { Target, Loader2, AlertTriangle, CheckCircle2, Shield } from 'lucide-react';
import { api } from '../lib/api';
import { PageHeader, Card, CardGlow, Tabs, Badge, Input, Button, scoreColor } from '../components/ui';

export default function MitrePage() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [tab, setTab] = useState('map');
  const [error, setError] = useState('');

  const go = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const r = await api.mitreCorrelate(domain.trim());
      setResult(r);
      setTab('map');
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  const score = result?.attack_score;
  const mapping = result?.mitre_mapping || [];
  const roadmap = result?.remediation_roadmap || {};

  const tacticColors: Record<string, string> = {
    'Initial Access': '#ef4444',
    Execution: '#f59e0b',
    Persistence: '#eab308',
    'Credential Access': '#22c55e',
    Discovery: '#06b6d4',
    'Defense Evasion': '#8b5cf6',
    'Lateral Movement': '#ec4899',
    Collection: '#f97316',
  };

  return (
    <div className="flex flex-col gap-4 animate-fade-in">
      <PageHeader
        icon={<Target size={18} className="text-mc-brand" />}
        title="MITRE ATT&CK Correlation"
        subtitle="Multi-vector risk analysis with framework mapping"
      />

      <CardGlow>
        <div className="flex gap-2.5">
          <Input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && go()}
            placeholder="Target domain"
            className="flex-1"
          />
          <Button onClick={go} disabled={loading || !domain.trim()}>
            {loading ? <Loader2 size={14} className="animate-spin-slow" /> : <Target size={14} />}
            {loading ? 'Analyzing...' : 'Generate'}
          </Button>
        </div>
        {error && <p className="text-rose-400 text-xs mt-2">{error}</p>}
      </CardGlow>

      {result && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <Card className="text-center">
              <div className="text-[10px] text-mc-txt3">Attack Score</div>
              <div className={`font-mono font-bold text-4xl ${scoreColor(100 - (score?.score || 0))}`}>
                {score?.score}
              </div>
              <div className={`text-[11px] font-semibold ${scoreColor(100 - (score?.score || 0))}`}>
                {score?.rating}
              </div>
            </Card>

            <Card>
              <div className="text-[10px] text-mc-txt3">Surface</div>
              <div className="text-sm font-semibold text-white mt-1">
                {result.attack_surface_summary?.external_posture}
              </div>
              <div className="text-[10px] text-mc-txt3 mt-1">
                Primary: {result.attack_surface_summary?.primary_exposure_vector}
              </div>
            </Card>

            <Card>
              <div className="text-[10px] text-mc-txt3">Attacker View</div>
              <div className="text-[11px] text-mc-txt2 mt-1">
                {result.attacker_view?.summary || 'Analysis complete'}
              </div>
            </Card>
          </div>

          <Tabs
            tabs={[
              { id: 'map', label: 'MITRE Mapping', count: mapping.length },
              { id: 'summary', label: 'Summary' },
              { id: 'road', label: 'Remediation' },
            ]}
            active={tab}
            onChange={setTab}
          />

          {tab === 'map' && (
            <div className="flex flex-col gap-1.5">
              {mapping.map((m: any, i: number) => {
                const col = tacticColors[m.tactic] || '#64748b';
                return (
                  <div key={i} style={{ ['--bl' as any]: col }}>
                    <Card className="!border-l-2 !border-l-[color:var(--bl)]">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span
                          className="text-[9px] font-mono px-2 py-0.5 rounded"
                          style={{ background: `${col}18`, color: col }}
                        >
                          {m.tactic}
                        </span>
                        <span className="text-xs font-semibold">{m.technique}</span>
                        <span className="font-mono text-[10px] text-mc-txt3">{m.technique_id}</span>
                        <span
                          className={`text-[8px] px-2 py-0.5 rounded-full ${
                            m.confidence === 'High'
                              ? 'bg-emerald-400/10 text-emerald-400'
                              : 'bg-amber-400/10 text-amber-400'
                          }`}
                        >
                          {m.confidence}
                        </span>
                      </div>
                      <div className="text-[10px] text-mc-txt3">{m.relevance || m.why_relevant}</div>
                    </Card>
                  </div>
                );
              })}
            </div>
          )}

          {tab === 'summary' && (
            <Card>
              <div className="flex items-center gap-2 mb-3">
                <Shield size={14} className="text-mc-brand" />
                <span className="text-xs font-semibold text-mc-txt2">Executive Summary</span>
              </div>

              <p className="text-xs text-mc-txt3 leading-relaxed">{result.executive_summary?.overview}</p>

              <div className="mt-3 space-y-1">
                {(score?.reasoning || result.executive_summary?.key_risks || []).map((r: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-[11px]">
                    <AlertTriangle size={12} className="text-amber-400 shrink-0" />
                    <span className="text-mc-txt2">{r}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {tab === 'road' && (
            <div className="flex flex-col gap-3">
              {(
                [
                  ['30 Days', roadmap.immediate_30_days],
                  ['60 Days', roadmap.short_term_60_days],
                  ['90 Days', roadmap.long_term_90_days],
                ] as const
              ).map(([ph, items]) =>
                items && (items as any[]).length > 0 ? (
                  <Card key={ph}>
                    <div className="text-xs font-semibold text-mc-txt2 mb-2">{ph}</div>
                    {(items as any[]).map((item: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-[11px] text-mc-txt2 py-1">
                        <CheckCircle2 size={12} className="text-emerald-400 mt-0.5 shrink-0" />
                        {typeof item === 'string' ? item : item.action}
                      </div>
                    ))}
                  </Card>
                ) : null
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
 

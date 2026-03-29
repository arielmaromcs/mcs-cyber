import { useState, useEffect, useRef } from 'react';
import { Shield, Plus, Trash2, RefreshCw, ChevronDown, ChevronUp, X, Play } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Button, Input, Spinner } from '../components/ui';

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

export default function NucleiPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [target, setTarget] = useState('');
  const [severity, setSeverity] = useState('critical,high,medium,low');
  const [description, setDescription] = useState('');
  const [scanning, setScanning] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const pollRef = useRef<any>(null);

  const load = async () => {
    setLoading(true);
    try { setScans(await (api as any).nucleiScans() || []); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const startScan = async () => {
    if (!target) return;
    setScanning(true);
    try {
      const res = await (api as any).nucleiScan({ target, severity, description });
      setShowForm(false);
      setTarget(''); setDescription('');
      setActiveScanId(res.scanId);
      load();
      pollRef.current = setInterval(async () => {
        const scan = await (api as any).nucleiGetScan(res.scanId);
        if (scan.status !== 'RUNNING') {
          clearInterval(pollRef.current);
          setActiveScanId(null);
          load();
        }
      }, 4000);
    } catch {}
    setScanning(false);
  };

  const delScan = async (id: string) => {
    if (!confirm('מחק סריקה זו?')) return;
    try { await (api as any).nucleiDeleteScan(id); load(); } catch {}
  };

  const scoreColor = (s: number) => s >= 80 ? 'text-emerald-400' : s >= 50 ? 'text-blue-400' : s >= 20 ? 'text-yellow-400' : 'text-red-400';

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[1000px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Shield size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">Nuclei Scanner</h1><p className="text-sm text-blue-100/60">סריקת vulnerabilities מתקדמת</p></div>
          </div>
          <Button onClick={() => setShowForm(true)}><Plus size={14} /> סריקה חדשה</Button>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto px-4 py-6">

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3 mb-5">
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-brand font-mono">{scans.length}</div><div className="text-[10px] text-mc-txt3">סה"כ סריקות</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-red-400 font-mono">{scans.filter(s => s.summary?.counts?.critical > 0).length}</div><div className="text-[10px] text-mc-txt3">עם Critical</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-emerald-400 font-mono">{scans.filter(s => s.status === 'COMPLETED').length}</div><div className="text-[10px] text-mc-txt3">הושלמו</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-yellow-400 font-mono">{scans.filter(s => s.status === 'RUNNING').length}</div><div className="text-[10px] text-mc-txt3">פעילות</div></Card>
        </div>

        {/* Form */}
        {showForm && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-mc-bg1 border border-mc-cardBorder rounded-2xl p-6 w-full max-w-md mx-4">
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-white">סריקת Nuclei חדשה</h3>
                <button onClick={() => setShowForm(false)}><X size={16} className="text-mc-txt3" /></button>
              </div>
              <div className="space-y-3">
                <Input label="Target *" value={target} onChange={(e: any) => setTarget(e.target.value)} placeholder="https://example.com או IP" />
                <div>
                  <label className="text-[10px] text-mc-txt3 mb-1 block">Severity</label>
                  <select value={severity} onChange={e => setSeverity(e.target.value)}
                    className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-3 py-2 text-xs text-mc-txt outline-none">
                    <option value="critical,high,medium,low">All (Critical → Low)</option>
                    <option value="critical,high">Critical + High בלבד</option>
                    <option value="critical">Critical בלבד</option>
                    <option value="medium,low">Medium + Low</option>
                  </select>
                </div>
                <Input label="תיאור (אופציונלי)" value={description} onChange={(e: any) => setDescription(e.target.value)} placeholder="שם לקוח / פרויקט" />
              </div>
              <div className="flex gap-2 mt-5">
                <Button onClick={startScan} disabled={scanning || !target}>
                  {scanning ? <><Spinner size={14} /> מריץ...</> : <><Play size={14} /> התחל סריקה</>}
                </Button>
                <Button variant="secondary" onClick={() => setShowForm(false)}>ביטול</Button>
              </div>
            </div>
          </div>
        )}

        {/* Active scan indicator */}
        {activeScanId && (
          <div className="mb-4 flex items-center gap-3 px-4 py-3 rounded-xl bg-mc-brand/10 border border-mc-brand/20">
            <Spinner size={16} className="text-mc-brand" />
            <span className="text-sm text-mc-brand">סריקה פעילה — עד 5 דקות...</span>
            <button onClick={load} className="ml-auto text-mc-txt3 hover:text-white"><RefreshCw size={14} /></button>
          </div>
        )}

        {/* Scans list */}
        {loading ? <div className="flex justify-center py-12"><Spinner size={24} className="text-mc-brand" /></div> : (
          <div className="space-y-3">
            {scans.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16">
                <Shield size={40} className="text-white/20 mb-4" />
                <div className="text-lg font-semibold text-white mb-2">אין סריקות</div>
                <div className="text-sm text-white/50">לחץ "סריקה חדשה" להתחלה</div>
              </div>
            ) : scans.map((s: any) => (
              <div key={s.id} className="bg-mc-card border border-mc-cardBorder rounded-xl overflow-hidden">
                <div className="p-4 flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-mc-brand/15 flex items-center justify-center shrink-0">
                    {s.status === 'RUNNING' ? <Spinner size={16} className="text-mc-brand" /> :
                     s.status === 'FAILED' ? <span className="text-red-400 text-xs font-bold">ERR</span> :
                     <span className={`text-lg font-bold font-mono ${scoreColor(s.summary?.score ?? 100)}`}>{s.summary?.score ?? '?'}</span>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-white truncate">{s.target}</span>
                      {s.description && <span className="text-[10px] text-mc-txt3">— {s.description}</span>}
                      <span className={`text-[9px] px-2 py-0.5 rounded-full font-semibold border ${
                        s.status === 'COMPLETED' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                        s.status === 'RUNNING' ? 'bg-mc-brand/15 text-mc-brand border-mc-brand/20' :
                        'bg-red-500/15 text-red-400 border-red-500/20'}`}>{s.status}</span>
                    </div>
                    {s.summary && (
                      <div className="flex gap-3">
                        {['critical','high','medium','low'].map(sev => (
                          s.summary.counts?.[sev] > 0 && (
                            <span key={sev} className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${SEV_COLORS[sev]}`}>
                              {sev[0].toUpperCase()}: {s.summary.counts[sev]}
                            </span>
                          )
                        ))}
                        <span className="text-[10px] text-mc-txt3">{s.summary.total} findings</span>
                      </div>
                    )}
                  </div>
                  <div className="flex gap-1 shrink-0">
                    {s.status === 'COMPLETED' && (
                      <button onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition">
                        פירוט {expandedId === s.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                      </button>
                    )}
                    <button onClick={() => delScan(s.id)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-red-400 transition"><Trash2 size={13} /></button>
                  </div>
                </div>

                {/* Findings panel */}
                {expandedId === s.id && s.findings && (
                  <div className="border-t border-mc-cardBorder bg-mc-bg2 p-4">
                    <div className="text-xs font-semibold text-white mb-3">תוצאות סריקה ({s.findings.length} ממצאים)</div>
                    {s.findings.length === 0 ? (
                      <div className="flex flex-col items-center py-6 gap-2">
                        <div className="w-12 h-12 rounded-full bg-emerald-500/15 flex items-center justify-center">
                          <span className="text-2xl">✅</span>
                        </div>
                        <div className="text-sm font-semibold text-emerald-400">לא נמצאו פגיעויות!</div>
                        <div className="text-[11px] text-mc-txt3 text-center max-w-xs">הסריקה בדקה CVEs, misconfigurations ו-exposures ידועות — הטארגט נקי.</div>
                        <div className="mt-3 grid grid-cols-3 gap-3 w-full max-w-sm">
                          <div className="bg-mc-bg1 rounded-lg p-2 text-center border border-mc-cardBorder">
                            <div className="text-xs font-bold text-mc-brand">CVE</div>
                            <div className="text-[10px] text-mc-txt3">נבדק</div>
                          </div>
                          <div className="bg-mc-bg1 rounded-lg p-2 text-center border border-mc-cardBorder">
                            <div className="text-xs font-bold text-mc-brand">Misconfig</div>
                            <div className="text-[10px] text-mc-txt3">נבדק</div>
                          </div>
                          <div className="bg-mc-bg1 rounded-lg p-2 text-center border border-mc-cardBorder">
                            <div className="text-xs font-bold text-mc-brand">Exposure</div>
                            <div className="text-[10px] text-mc-txt3">נבדק</div>
                          </div>
                        </div>
                        <div className="text-[10px] text-mc-txt3 mt-1">טארגט: <span className="font-mono text-white">{s.target}</span> • {new Date(s.completed_at).toLocaleString('he-IL')}</div>
                      </div>
                    ) : (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {s.findings.map((f: any, i: number) => (
                        <div key={i} className={`px-3 py-2.5 rounded-lg border ${SEV_COLORS[f.severity] || SEV_COLORS.info}`}>
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase border ${SEV_COLORS[f.severity] || SEV_COLORS.info}`}>{f.severity}</span>
                            <span className="text-xs font-semibold text-white">{f.name}</span>
                            {f.cve && <span className="text-[10px] text-mc-brand font-mono">{f.cve}</span>}
                          </div>
                          {f.matched && <div className="text-[10px] text-mc-txt3 font-mono truncate">{f.matched}</div>}
                          {f.description && <div className="text-[10px] text-mc-txt3 mt-1">{f.description}</div>}
                        </div>
                      ))}
                    </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

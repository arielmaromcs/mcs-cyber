import { useState, useEffect } from 'react';
import { Rss, RefreshCw, Shield, AlertTriangle, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Button, Spinner } from '../components/ui';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
};

const SEV_BAR: Record<string, string> = {
  CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500', LOW: 'bg-blue-500'
};

export default function CvePage() {
  const [cves, setCves] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [lang, setLang] = useState<'he'|'en'>('he');

  const load = async () => {
    setLoading(true);
    try {
      const [cveData, statsData] = await Promise.all([
        (api as any).cveList('limit=100'),
        (api as any).cveStats(),
      ]);
      setCves(cveData || []);
      setStats(statsData || null);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const refresh = async () => {
    setRefreshing(true);
    try { await (api as any).post('/api/cve/refresh', {}); await load(); } catch {}
    setRefreshing(false);
  };

  const filtered = cves.filter(c =>
    !filter || c.severity === filter
  );

  const statCounts: Record<string, number> = {};
  (stats?.bySeverity || []).forEach((s: any) => { statCounts[s.severity] = s.count; });

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[1000px] mx-auto flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
              <Rss size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">CVE Intelligence Feed</h1>
              <p className="text-sm text-blue-100/60">פגיעויות רלוונטיות • Windows/AD • VMware • Cisco • Fortinet</p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setLang(lang === 'he' ? 'en' : 'he')}>
              {lang === 'he' ? '🇺🇸 English' : '🇮🇱 עברית'}
            </Button>
            <Button onClick={refresh} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
              {refreshing ? 'מעדכן...' : 'עדכן עכשיו'}
            </Button>
          </div>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto px-4 py-6">
        {/* Stats */}
        <div className="grid grid-cols-5 gap-3 mb-5">
          <div className="bg-mc-card border border-mc-cardBorder rounded-xl p-4 text-center cursor-pointer hover:border-mc-brand/40 transition" onClick={() => setFilter('')}>
            <div className="text-2xl font-bold text-mc-brand font-mono">{stats?.total || 0}</div>
            <div className="text-[10px] text-mc-txt3">סה"כ</div>
          </div>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => (
            <div key={sev} className={`bg-mc-card border border-mc-cardBorder rounded-xl p-4 text-center cursor-pointer transition hover:border-mc-brand/40 ${filter === sev ? 'border-mc-brand/50' : ''}`} onClick={() => setFilter(filter === sev ? '' : sev)}>
              <div className={`text-2xl font-bold font-mono ${SEV_COLORS[sev].split(' ')[0]}`}>{statCounts[sev] || 0}</div>
              <div className="text-[10px] text-mc-txt3">{sev}</div>
            </div>
          ))}
        </div>

        {/* Last updated */}
        {stats?.lastUpdated && (
          <div className="text-[11px] text-mc-txt3 mb-4 flex items-center gap-1">
            <Shield size={11} /> עודכן לאחרונה: {new Date(stats.lastUpdated).toLocaleString('he-IL')}
          </div>
        )}

        {/* CVE List */}
        {loading ? (
          <div className="flex justify-center py-16"><Spinner size={24} className="text-mc-brand" /></div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center py-16 gap-3">
            <Rss size={40} className="text-white/20" />
            <div className="text-lg font-semibold text-white">אין נתונים</div>
            <div className="text-sm text-white/50">לחץ "עדכן עכשיו" למשיכת CVEs חדשים</div>
            <Button onClick={refresh} disabled={refreshing}>
              <RefreshCw size={14} /> משוך CVEs
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((c: any) => (
              <div key={c.id} className="bg-mc-card border border-mc-cardBorder rounded-xl overflow-hidden">
                <div className="p-4 flex items-start gap-3 cursor-pointer" onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}>
                  {/* Severity indicator */}
                  <div className={`w-1 self-stretch rounded-full shrink-0 ${SEV_BAR[c.severity] || 'bg-slate-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="text-sm font-bold text-white font-mono">{c.id}</span>
                      <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold border ${SEV_COLORS[c.severity] || SEV_COLORS.LOW}`}>{c.severity}</span>
                      {c.cvss_score && <span className="text-[10px] text-mc-txt3">CVSS {c.cvss_score}</span>}
                      {c.is_exploited && <span className="text-[9px] px-2 py-0.5 rounded-full font-bold bg-orange-500/15 text-orange-400 border border-orange-500/20">⚠️ EXPLOITED</span>}
                      {c.ai_relevance_score >= 8 && <span className="text-[9px] px-2 py-0.5 rounded-full font-bold bg-red-500/15 text-red-400 border border-red-500/20">🔥 רלוונטי מאוד</span>}
                    </div>
                    {/* AI Summary */}
                    {lang === 'he' && c.ai_summary_he ? (
                      <p className="text-[12px] text-mc-txt2 leading-relaxed mb-2 line-clamp-2" dir="rtl">{c.ai_summary_he}</p>
                    ) : c.ai_summary_en ? (
                      <p className="text-[12px] text-mc-txt2 leading-relaxed mb-2 line-clamp-2">{c.ai_summary_en}</p>
                    ) : (
                      <p className="text-[12px] text-mc-txt3 leading-relaxed mb-2 line-clamp-2">{c.description?.substring(0, 150)}...</p>
                    )}
                    <div className="flex items-center gap-2 flex-wrap">
                      {(c.tags || []).map((t: string) => (
                        <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-mc-brand/10 text-mc-brand border border-mc-brand/20">{t}</span>
                      ))}
                      <span className="text-[10px] text-mc-txt3 ml-auto">{new Date(c.published_at).toLocaleDateString('he-IL')}</span>
                    </div>
                  </div>
                  <div className="shrink-0 text-mc-txt3">
                    {expandedId === c.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </div>
                </div>

                {/* Expanded */}
                {expandedId === c.id && (
                  <div className="border-t border-mc-cardBorder bg-mc-bg2 p-4 space-y-3">
                    {/* Full description */}
                    <div>
                      <div className="text-[10px] text-mc-txt3 uppercase font-semibold mb-1">תיאור מלא</div>
                      <p className="text-[12px] text-mc-txt leading-relaxed">{c.description}</p>
                    </div>
                    {/* AI insights */}
                    {(c.ai_summary_he || c.ai_summary_en) && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {c.ai_summary_he && (
                          <div className="bg-mc-bg1 rounded-lg p-3 border border-mc-cardBorder">
                            <div className="text-[10px] text-mc-brand font-semibold mb-1">🇮🇱 תובנת AI</div>
                            <p className="text-[12px] text-mc-txt2 leading-relaxed" dir="rtl">{c.ai_summary_he}</p>
                          </div>
                        )}
                        {c.ai_summary_en && (
                          <div className="bg-mc-bg1 rounded-lg p-3 border border-mc-cardBorder">
                            <div className="text-[10px] text-mc-brand font-semibold mb-1">🔍 AI Insight</div>
                            <p className="text-[12px] text-mc-txt2 leading-relaxed">{c.ai_summary_en}</p>
                          </div>
                        )}
                      </div>
                    )}
                    {/* References */}
                    {(c.references || []).length > 0 && (
                      <div>
                        <div className="text-[10px] text-mc-txt3 uppercase font-semibold mb-1">קישורים</div>
                        <div className="space-y-1">
                          {(c.references || []).slice(0, 3).map((ref: string, i: number) => (
                            <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                              className="flex items-center gap-1 text-[11px] text-mc-brand hover:underline truncate">
                              <ExternalLink size={10} /> {ref}
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                    <a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] text-mc-brand hover:underline">
                      <ExternalLink size={11} /> פרטים ב-NVD
                    </a>
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

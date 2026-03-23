import { useState, useEffect } from 'react';
import { Shield, Lock, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronUp, Search, Clock, Heart, Download, History } from 'lucide-react';
import { api } from '../lib/api';
import { generateTlsReport, downloadReport } from '../lib/reportGenerator';
import { Card, Button, Input, Spinner } from '../components/ui';

const HISTORY_KEY = 'tls_scan_history';

export default function TlsScan() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [openVersion, setOpenVersion] = useState<string | null>(null);
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    try { setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]')); } catch {}
  }, []);

  const saveToHistory = (res: any) => {
    const entry = { host: res.host, scannedAt: res.scannedAt, certDaysLeft: res.cert?.daysLeft, secureVersions: res.versions?.filter((v: any) => v.supported && v.risk === 'good').length, weakVersions: res.versions?.filter((v: any) => v.supported && v.risk === 'high').length };
    const updated = [entry, ...history.filter(h => h.host !== res.host)].slice(0, 10);
    setHistory(updated);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
  };

  const scan = async () => {
    setLoading(true); setError(''); setResult(null);
    try {
      const data = await (api as any).tlsScan(target);
      setResult(data);
      saveToHistory(data);
      const supported = data.versions?.filter((r: any) => r.supported && r.risk === 'good');
      if (supported?.length) setOpenVersion(supported[supported.length - 1].version);
    } catch (e: any) { setError(e.message || 'Scan failed'); }
    setLoading(false);
  };

  const riskBadge = (risk: string) => {
    if (risk === 'high') return 'text-red-400 bg-red-500/10 border-red-500/20';
    if (risk === 'good') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
    return 'text-mc-txt3 bg-white/5 border-white/10';
  };

  const gradeBadge = (grade: string) => {
    if (grade === 'A') return 'text-emerald-400 bg-emerald-500/10';
    if (grade === 'B') return 'text-blue-400 bg-blue-500/10';
    if (grade === 'C') return 'text-amber-400 bg-amber-500/10';
    return 'text-red-400 bg-red-500/10';
  };

  const certColor = (days: number | null) => {
    if (days === null) return 'text-mc-txt3';
    if (days < 14) return 'text-red-400';
    if (days < 30) return 'text-amber-400';
    return 'text-emerald-400';
  };

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[1000px] mx-auto">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
              <Lock size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">TLS Scanner</h1>
              <p className="text-sm text-blue-100/60">Full TLS/SSL analysis — protocols, ciphers, certificate & vulnerabilities</p>
            </div>
          </div>
          <div className="flex gap-2">
            <div className="flex-1">
              <input value={target} onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !loading && target && scan()}
                placeholder="example.com or https://example.com"
                className="w-full px-4 py-3 bg-white/8 border border-white/15 rounded-xl text-white placeholder:text-white/30 focus:border-mc-brand/50 outline-none text-sm font-mono" />
            </div>
            <Button onClick={scan} disabled={loading || !target} size="lg">
              {loading ? <><Spinner size={14} /> Scanning...</> : <><Search size={14} /> Scan</>}
            </Button>
          </div>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto px-4 py-6">
        {error && <div className="mb-4 text-xs text-red-400">{error}</div>}

        {loading && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <Spinner size={28} className="text-mc-brand" />
            <div className="text-sm text-mc-txt3">Running full TLS analysis with sslscan...</div>
            <div className="text-xs text-mc-txt3">This may take up to 30 seconds</div>
          </div>
        )}

        {!result && !loading && (
          <>
            {/* Info Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🔐</div>
                <h3 className="text-sm font-semibold text-white mb-1">Protocol Analysis</h3>
                <p className="text-xs text-white/40">Detects supported TLS/SSL versions including deprecated SSLv2, SSLv3, TLSv1.0 and TLSv1.1 that should be disabled.</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🔑</div>
                <h3 className="text-sm font-semibold text-white mb-1">Cipher Suite Audit</h3>
                <p className="text-xs text-white/40">Lists all supported cipher suites with strength grades, identifies weak ciphers (RC4, DES, 3DES) and confirms PFS support.</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">📜</div>
                <h3 className="text-sm font-semibold text-white mb-1">Certificate Inspection</h3>
                <p className="text-xs text-white/40">Validates certificate expiry, issuer, subject and SANs. Alerts on certificates expiring within 30 days or already expired.</p>
              </div>
            </div>

            {/* History */}
            {history.length > 0 && (
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <History size={14} className="text-mc-txt3" />
                  <span className="text-sm font-semibold text-white">Recent Scans</span>
                </div>
                <div className="space-y-1">
                  {history.map((h, i) => (
                    <div key={i} onClick={() => setTarget(h.host)}
                      className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-mc-brand/5 cursor-pointer transition">
                      <Lock size={12} className="text-mc-txt3" />
                      <span className="text-xs font-mono text-white flex-1">{h.host}</span>
                      <span className="text-[10px] text-emerald-400">{h.secureVersions} secure</span>
                      {h.weakVersions > 0 && <span className="text-[10px] text-red-400">{h.weakVersions} weak</span>}
                      <span className={`text-[10px] font-mono ${certColor(h.certDaysLeft)}`}>{h.certDaysLeft}d</span>
                      <span className="text-[10px] text-mc-txt3">{new Date(h.scannedAt).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}

        {result && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button onClick={() => downloadReport(generateTlsReport(result, result.host), `tls-scan-${result.host}.html`)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-xs font-medium hover:bg-mc-brand/20 transition">
                <Download size={14} /> Download Report
              </button>
            </div>

            {result.cert && (
              <Card className="p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Shield size={16} className="text-mc-brand" />
                  <span className="text-sm font-semibold text-white">Certificate</span>
                  {result.cert.daysLeft !== null && (
                    <span className={`ml-auto text-xs font-mono font-bold ${certColor(result.cert.daysLeft)}`}>
                      {result.cert.daysLeft > 0 ? `${result.cert.daysLeft} days left` : '⚠ EXPIRED'}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  {result.cert.subject && <div><span className="text-mc-txt3">Subject: </span><span className="text-white">{result.cert.subject}</span></div>}
                  {result.cert.issuer && <div><span className="text-mc-txt3">Issuer: </span><span className="text-white">{result.cert.issuer}</span></div>}
                  {result.cert.validFrom && <div><span className="text-mc-txt3">From: </span><span className="text-white">{result.cert.validFrom}</span></div>}
                  {result.cert.validTo && <div><span className="text-mc-txt3">To: </span><span className={certColor(result.cert.daysLeft)}>{result.cert.validTo}</span></div>}
                  {result.cert.sans?.length > 0 && (
                    <div className="md:col-span-2"><span className="text-mc-txt3">SANs: </span><span className="text-white">{result.cert.sans.slice(0,8).join(', ')}{result.cert.sans.length > 8 ? ` +${result.cert.sans.length - 8} more` : ''}</span></div>
                  )}
                </div>
              </Card>
            )}

            <Card className="p-4">
              <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-3">Security Features</div>
              <div className="flex flex-wrap gap-2">
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${result.fallbackScsv ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : 'text-red-400 bg-red-500/10 border-red-500/20'}`}>
                  {result.fallbackScsv ? <CheckCircle2 size={12} /> : <XCircle size={12} />} TLS Fallback SCSV
                </div>
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${result.renegotiation ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : 'text-amber-400 bg-amber-500/10 border-amber-500/20'}`}>
                  {result.renegotiation ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />} Secure Renegotiation
                </div>
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${!result.compression ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : 'text-red-400 bg-red-500/10 border-red-500/20'}`}>
                  {!result.compression ? <CheckCircle2 size={12} /> : <XCircle size={12} />} Compression {result.compression ? 'Enabled (CRIME risk)' : 'Disabled'}
                </div>
                {result.heartbleed && Object.entries(result.heartbleed).map(([ver, vuln]: any) => (
                  <div key={ver} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${vuln ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'}`}>
                    <Heart size={12} /> {ver} Heartbleed: {vuln ? 'VULNERABLE' : 'Safe'}
                  </div>
                ))}
              </div>
            </Card>

            <div>
              <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-3">TLS / SSL Versions & Ciphers</div>
              <div className="space-y-2">
                {result.versions?.map((r: any) => (
                  <Card key={r.version} className="overflow-hidden">
                    <button onClick={() => r.supported && setOpenVersion(openVersion === r.version ? null : r.version)}
                      className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition">
                      <div className={`px-2.5 py-1 rounded-lg border text-[11px] font-bold font-mono ${riskBadge(r.risk)}`}>{r.version}</div>
                      <div className="flex-1 text-left">
                        <div className="flex items-center gap-2">
                          {r.supported ? (r.risk === 'high' ? <AlertTriangle size={14} className="text-red-400" /> : <CheckCircle2 size={14} className="text-emerald-400" />) : <XCircle size={14} className="text-mc-txt3" />}
                          <span className="text-sm font-medium text-white">{r.supported ? 'Supported' : 'Not Supported'}</span>
                        </div>
                        <div className="text-[10px] text-mc-txt3 mt-0.5">{r.note}</div>
                      </div>
                      {r.supported && r.ciphers?.length > 0 && <span className="text-[10px] text-mc-txt3">{r.ciphers.length} cipher{r.ciphers.length !== 1 ? 's' : ''}</span>}
                      {r.supported && (openVersion === r.version ? <ChevronUp size={14} className="text-mc-txt3" /> : <ChevronDown size={14} className="text-mc-txt3" />)}
                    </button>
                    {openVersion === r.version && r.ciphers?.length > 0 && (
                      <div className="px-5 pb-4 border-t border-mc-cardBorder">
                        <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mt-3 mb-2">Cipher Suites</div>
                        <div className="space-y-1">
                          {r.ciphers.map((c: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.02] border border-white/5">
                              <span className={`text-[10px] font-bold w-5 h-5 rounded flex items-center justify-center shrink-0 ${gradeBadge(c.grade)}`}>{c.grade}</span>
                              <span className="text-xs font-mono text-white flex-1">{c.name}</span>
                              <span className="text-[10px] text-mc-txt3">{c.bits} bits</span>
                              {c.extra && <span className="text-[10px] text-mc-txt3 hidden md:block">{c.extra}</span>}
                              <div className="flex gap-1">
                                {c.isWeak && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">WEAK</span>}
                                {c.isPFS && !c.isWeak && <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">PFS</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                ))}
              </div>
            </div>

            <Card className="p-4">
              <div className="flex items-center gap-2 mb-3">
                <Clock size={14} className="text-mc-txt3" />
                <span className="text-[10px] text-mc-txt3">Scanned: {result.host} — {new Date(result.scannedAt).toLocaleString()}</span>
              </div>
              <div className="grid grid-cols-4 gap-3 text-center">
                <div><div className="text-lg font-bold font-mono text-emerald-400">{result.versions?.filter((r: any) => r.supported && r.risk === 'good').length}</div><div className="text-[10px] text-mc-txt3">Secure Versions</div></div>
                <div><div className="text-lg font-bold font-mono text-red-400">{result.versions?.filter((r: any) => r.supported && r.risk === 'high').length}</div><div className="text-[10px] text-mc-txt3">Weak Versions</div></div>
                <div><div className="text-lg font-bold font-mono text-mc-brand">{result.versions?.reduce((a: number, r: any) => a + (r.ciphers?.length || 0), 0)}</div><div className="text-[10px] text-mc-txt3">Total Ciphers</div></div>
                <div><div className={`text-lg font-bold font-mono ${certColor(result.cert?.daysLeft)}`}>{result.cert?.daysLeft ?? '?'}</div><div className="text-[10px] text-mc-txt3">Cert Days Left</div></div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

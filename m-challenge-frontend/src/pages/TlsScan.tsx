import { useState } from 'react';
import { Shield, Lock, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronUp, Search, Clock } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Button, Input, Spinner } from '../components/ui';

export default function TlsScan() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [openVersion, setOpenVersion] = useState<string | null>(null);

  const scan = async () => {
    setLoading(true); setError(''); setResult(null);
    try {
      const data = await (api as any).tlsScan(target);
      setResult(data);
      const supported = data.results?.filter((r: any) => r.supported);
      if (supported?.length) setOpenVersion(supported[supported.length - 1].version);
    } catch (e: any) {
      setError(e.message || 'Scan failed');
    }
    setLoading(false);
  };

  const riskColor = (risk: string) => {
    if (risk === 'high') return 'text-red-400 bg-red-500/10 border-red-500/20';
    if (risk === 'good') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
    return 'text-mc-txt3 bg-white/5 border-white/10';
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
        <div className="max-w-[900px] mx-auto flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
            <Lock size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">TLS Scanner</h1>
            <p className="text-sm text-blue-100/60">Analyze TLS versions and cipher suites for any domain</p>
          </div>
        </div>
      </div>

      <div className="max-w-[900px] mx-auto px-4 py-6">
        <Card className="p-4 mb-6">
          <div className="flex gap-3">
            <div className="flex-1">
              <Input
                label="Domain or URL"
                value={target}
                onChange={(e: any) => setTarget(e.target.value)}
                placeholder="example.com or https://example.com"
                onKeyDown={(e: any) => e.key === 'Enter' && !loading && target && scan()}
              />
            </div>
            <div className="flex items-end">
              <Button onClick={scan} disabled={loading || !target}>
                {loading ? <Spinner size={14} /> : <><Search size={14} /> Scan</>}
              </Button>
            </div>
          </div>
          {error && <div className="mt-3 text-xs text-red-400">{error}</div>}
        </Card>

        {loading && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <Spinner size={28} className="text-mc-brand" />
            <div className="text-sm text-mc-txt3">Scanning TLS configuration...</div>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            {/* Certificate Info */}
            {result.cert && (
              <Card className="p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Shield size={16} className="text-mc-brand" />
                  <span className="text-sm font-semibold text-white">Certificate Info</span>
                  {result.cert.daysLeft !== null && (
                    <span className={`ml-auto text-xs font-mono font-semibold ${certColor(result.cert.daysLeft)}`}>
                      {result.cert.daysLeft > 0 ? `${result.cert.daysLeft} days left` : 'EXPIRED'}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  {result.cert.subject && (
                    <div><span className="text-mc-txt3">Subject: </span><span className="text-white">{result.cert.subject}</span></div>
                  )}
                  {result.cert.issuer && (
                    <div><span className="text-mc-txt3">Issuer: </span><span className="text-white">{result.cert.issuer}</span></div>
                  )}
                  {result.cert.validFrom && (
                    <div><span className="text-mc-txt3">Valid From: </span><span className="text-white">{result.cert.validFrom}</span></div>
                  )}
                  {result.cert.validTo && (
                    <div className="flex items-center gap-1">
                      <span className="text-mc-txt3">Valid To: </span>
                      <span className={certColor(result.cert.daysLeft)}>{result.cert.validTo}</span>
                      {result.cert.daysLeft !== null && result.cert.daysLeft < 30 && (
                        <AlertTriangle size={12} className="text-amber-400" />
                      )}
                    </div>
                  )}
                  {result.cert.sans?.length > 0 && (
                    <div className="md:col-span-2">
                      <span className="text-mc-txt3">SANs: </span>
                      <span className="text-white">{result.cert.sans.join(', ')}</span>
                    </div>
                  )}
                </div>
              </Card>
            )}

            {/* TLS Versions */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-mc-txt3 uppercase tracking-wider mb-3">TLS Versions</div>
              {result.results?.map((r: any) => (
                <Card key={r.version} className="overflow-hidden">
                  <button
                    onClick={() => r.supported && setOpenVersion(openVersion === r.version ? null : r.version)}
                    className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition"
                  >
                    <div className={`px-2.5 py-1 rounded-lg border text-[11px] font-bold font-mono ${riskColor(r.risk)}`}>
                      {r.version}
                    </div>
                    <div className="flex-1 text-left">
                      <div className="flex items-center gap-2">
                        {r.supported ? (
                          r.risk === 'high' ? <AlertTriangle size={14} className="text-red-400" /> : <CheckCircle2 size={14} className="text-emerald-400" />
                        ) : (
                          <XCircle size={14} className="text-mc-txt3" />
                        )}
                        <span className="text-sm font-medium text-white">
                          {r.supported ? 'Supported' : 'Not Supported'}
                        </span>
                      </div>
                      <div className="text-[10px] text-mc-txt3 mt-0.5">{r.note}</div>
                    </div>
                    {r.supported && r.ciphers?.length > 0 && (
                      <span className="text-[10px] text-mc-txt3">{r.ciphers.length} cipher{r.ciphers.length !== 1 ? 's' : ''}</span>
                    )}
                    {r.supported && (openVersion === r.version ? <ChevronUp size={14} className="text-mc-txt3" /> : <ChevronDown size={14} className="text-mc-txt3" />)}
                  </button>

                  {openVersion === r.version && r.ciphers?.length > 0 && (
                    <div className="px-5 pb-4 border-t border-mc-cardBorder">
                      <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mt-3 mb-2">Cipher Suites</div>
                      <div className="space-y-1">
                        {r.ciphers.map((c: string) => {
                          const isWeak = /RC4|DES|MD5|NULL|EXPORT|anon/i.test(c);
                          const isPFS = /ECDHE|DHE/i.test(c);
                          return (
                            <div key={c} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5">
                              <span className="text-xs font-mono text-white flex-1">{c}</span>
                              {isWeak && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">WEAK</span>}
                              {isPFS && !isWeak && <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">PFS</span>}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>

            {/* Summary */}
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-3">
                <Clock size={14} className="text-mc-txt3" />
                <span className="text-[10px] text-mc-txt3">Scanned at {new Date(result.scannedAt).toLocaleString()}</span>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div>
                  <div className="text-lg font-bold font-mono text-emerald-400">{result.results?.filter((r: any) => r.supported && r.risk === 'good').length}</div>
                  <div className="text-[10px] text-mc-txt3">Secure Versions</div>
                </div>
                <div>
                  <div className="text-lg font-bold font-mono text-red-400">{result.results?.filter((r: any) => r.supported && r.risk === 'high').length}</div>
                  <div className="text-[10px] text-mc-txt3">Weak Versions</div>
                </div>
                <div>
                  <div className={`text-lg font-bold font-mono ${certColor(result.cert?.daysLeft)}`}>{result.cert?.daysLeft ?? '?'}</div>
                  <div className="text-[10px] text-mc-txt3">Cert Days Left</div>
                </div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

import { useLang } from '../hooks/useLang';
import ScanHistory from '../components/ScanHistory';
import { useState, useEffect, useRef } from 'react';
import { Mail, Loader2, CheckCircle2, ExternalLink, AlertTriangle, Globe, Lock, Shield, Server, Eye, Clock, Search, Download } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { generateEmailReport, downloadReport } from '../lib/reportGenerator';
import { Card, Badge, ProgressCircle, Tabs, Button, ScoreDisplay, EmptyState, Spinner, sevColor } from '../components/ui';

const STAGES = ['DNS_LOOKUP', 'SPF_ANALYSIS', 'DKIM_ANALYSIS', 'DMARC_ANALYSIS', 'MX_ANALYSIS', 'WHOIS', 'SMTP_CAPABILITY', 'BLACKLIST_CHECK', 'PORT_SCAN', 'ABUSEIPDB', 'FINALIZATION'];
const SCORE_LABELS: Record<string, { max: number; label: string }> = {
  spf: { max: 18, label: 'SPF' }, dkim: { max: 18, label: 'DKIM' }, dmarc: { max: 22, label: 'DMARC' },
  relay: { max: 18, label: 'Relay Protection' }, misc: { max: 12, label: 'Infrastructure' }, ports: { max: 12, label: 'Port Security' },
};

export default function EmailScan() {
  const { t } = useLang();
  const { user } = useAuth();
  const [domain, setDomain] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('score');
  const pollRef = useRef<ReturnType<typeof setInterval>>();
  const guestCount = parseInt(localStorage.getItem('email_guest_scans_count') || '0');

  const startScan = async () => {
    if (!domain.trim() || isStarting) return;
    if (!user && guestCount >= 5) { setError('הגעת לגבול של 5 סריקות חינם. התחבר כדי להמשיך.'); return; }
    setError(''); setIsStarting(true); setResult(null); setScanId(null); setStatus(null); setTab('progress');
    try {
      const d = domain.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '').toLowerCase();
      const data = await api.startEmailScan(d);
      setScanId(data.scan_id);
      if (!user) localStorage.setItem('email_guest_scans_count', String(guestCount + 1));
    } catch (e: any) { setError(e.message); setTab('score'); } finally { setIsStarting(false); }
  };

  useEffect(() => {
    if (!scanId) return;
    const poll = async () => {
      try {
        const s = await api.emailScanStatus(scanId);
        setStatus(s);
        if (s.status === 'COMPLETED' || s.status === 'FAILED') {
          clearInterval(pollRef.current);
          if (s.status === 'COMPLETED') { const r = await api.emailScanResult(scanId); setResult(r); setTab('score'); }
          else setError('Scan failed');
        }
      } catch {}
    };
    poll();
    pollRef.current = setInterval(poll, 2500);
    return () => clearInterval(pollRef.current);
  }, [scanId]);

  const loadHistoryScan = (id: string) => {
    setScanId(id); setResult(null); setStatus(null); setTab('progress');
    api.emailScanResult(id).then((r: any) => {
      if (r.status === 'COMPLETED') { setResult(r); setTab('score'); }
    }).catch(() => {});
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sid = params.get("scan");
    if (sid) loadHistoryScan(sid);
  }, []);

  const isRunning = status && (status.status === 'RUNNING' || status.status === 'PENDING');
  const isComplete = result?.status === 'COMPLETED';
  const bd = result?.scoreBreakdown || result?.score_breakdown || {};
  const dns = result?.dnsRecords || result?.dns_records || {};
  const spf = result?.spfRecord || result?.spf_record || {};
  const dkim = result?.dkimRecord || result?.dkim_record || {};
  const dmarc = result?.dmarcRecord || result?.dmarc_record || {};
  const mx = result?.mxAnalysis || result?.mx_analysis || {};
  const whois = result?.whoisInfo || result?.whois_info || {};
  const smtp = result?.smtpTests || result?.smtp_tests || {};
  const bl = result?.blacklistStatus || result?.blacklist_status || {};
  const abuse = result?.abuseipdb || {};
  const mxLinks = result?.mxtoolboxLinks || result?.mxtoolbox_links || {};
  const findings = result?.findings || [];
  const recs = result?.recommendations || [];

  return (
    <div>
      {/* Hero */}
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Mail size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">{t("Email Security Scanner")}</h1><p className="text-sm text-blue-100/60">{t("SPF, DKIM, DMARC, Blacklist & Reputation Analysis")}</p></div>
          </div>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && startScan()}
                placeholder={t("Enter domain placeholder")}
                className="w-full px-4 py-3 bg-white/8 border border-white/15 rounded-xl text-white placeholder:text-white/30 focus:border-mc-brand/50 outline-none text-sm font-mono" />
            </div>
            <Button onClick={startScan} disabled={isStarting || !domain.trim()} size="lg">
              {isStarting ? <><Spinner size={14} /> Scanning...</> : 'Scan Domain'}
            </Button>
          </div>
          {!user && <div className="mt-2 text-[11px] text-blue-200/40">{Math.max(0, 5 - guestCount)} free scans remaining</div>}
          {error && <div className="mt-2 text-sm text-mc-rose">{error}</div>}
        </div>
      </div>

      <div className="max-w-[1100px] mx-auto px-4 py-6">
        {/* Progress */}
        {isRunning && status && (
          <Card className="p-5 mb-5 animate-fadeIn">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2"><Loader2 size={16} className="text-mc-brand animate-spin" /><span className="text-sm font-semibold text-white">Stage: {status.currentStage || status.current_stage || 'Initializing'}</span></div>
              <span className="text-xs text-mc-txt3 font-mono">{status.progress}%</span>
            </div>
            <div className="progress-track rounded-full h-1.5"><div className="progress-fill h-full rounded-full transition-all" style={{ width: `${status.progress}%` }} /></div>
            <div className="flex gap-1 mt-3">
              {STAGES.map((s, i) => {
                const idx = STAGES.indexOf(status.currentStage || status.current_stage || '');
                return <div key={s} className={`flex-1 h-1 rounded-full ${i < idx ? 'bg-mc-emerald' : i === idx ? 'bg-mc-brand animate-pulse-slow' : 'bg-mc-bg2'}`} title={s.replace(/_/g, ' ')} />;
              })}
            </div>
          </Card>
        )}

        {/* Results */}
        {isComplete && result && (
          <div className="animate-fadeInUp">
            {/* Top Score */}
            <Card glow className="p-6 mb-5 flex items-center gap-8">
              <ProgressCircle value={result.emailSecurityScore || result.email_security_score || 0} size={80} stroke={5} />
              <div className="flex-1">
                <div className="flex items-center gap-3"><div className="text-lg font-bold text-white mb-1">{t("Email Security Score")}</div>
                  <button onClick={() => downloadReport(generateEmailReport(result, domain), `email-scan-${domain}.html`)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition">
                    <Download size={13} /> {t("Download Report")}
                  </button></div>
                <div className="text-xs text-mc-txt3">{result.scoreRating || result.score_rating || 'N/A'} • {result.domain}</div>
              </div>
              {findings.length > 0 && <div className="text-right"><div className="text-2xl font-bold text-mc-rose">{findings.length}</div><div className="text-[10px] text-mc-txt3">Issues</div></div>}
            </Card>

            {/* 8 Tabs */}
            <Tabs active={tab} onChange={setTab} tabs={[
              { key: 'score', label: 'Score' },
              { key: 'exposure', label: 'Exposure' },
              { key: 'dns', label: 'DNS & Email Config' },
              { key: 'whois', label: 'WHOIS' },
              { key: 'blacklist', label: 'Blacklist' },
              { key: 'reputation', label: 'IP Reputation' },
              { key: 'tools', label: 'MXToolbox' },
              { key: 'recommendations', label: 'Recommendations', count: recs.length },
            ]} />

            {/* Tab 1: Score Breakdown */}
            {tab === 'score' && (
              <div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
                  {Object.entries(SCORE_LABELS).map(([key, { max, label }]) => {
                    const val = bd[key] || 0; const pct = (val / max) * 100;
                    return (
                      <Card key={key} className="p-4">
                        <div className="text-[10px] text-mc-txt3 uppercase tracking-wider mb-2">{label}</div>
                        <div className="flex items-end gap-1.5"><span className="text-2xl font-bold font-mono text-white">{val}</span><span className="text-xs text-mc-txt3 mb-0.5">/ {max}</span></div>
                        <div className="mt-2 progress-track rounded-full h-1.5"><div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: pct >= 80 ? '#34d399' : pct >= 50 ? '#2d7aff' : '#fbbf24' }} /></div>
                      </Card>
                    );
                  })}
                </div>
                {findings.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold text-white">Findings</h3>
                    {findings.map((f: any, i: number) => (
                      <Card key={i} className="px-4 py-3 flex items-start gap-2">
                        <AlertTriangle size={14} className={`${sevColor(f.severity).text} mt-0.5 shrink-0`} />
                        <div><div className="text-xs text-white font-medium">{f.title}</div><div className="text-[11px] text-mc-txt3">{f.description}</div></div>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab 2: Exposure */}
            {tab === 'exposure' && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">{(dns.a_records || []).length}</div><div className="text-[10px] text-mc-txt3">IP Addresses (A)</div></Card>
                <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">{(dns.mx_records || mx.records || []).length}</div><div className="text-[10px] text-mc-txt3">Mail Servers (MX)</div></Card>
                <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">{(dns.ns_records || []).length}</div><div className="text-[10px] text-mc-txt3">Name Servers</div></Card>
                <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">{(dns.txt_records || []).length}</div><div className="text-[10px] text-mc-txt3">TXT Records</div></Card>
              </div>
            )}

            {/* Tab 3: DNS & Email Config */}
            {tab === 'dns' && (
              <div className="space-y-4">
                {/* DNS Records */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-3">DNS Records</h3>
                  {['a', 'aaaa', 'ns', 'txt'].map(type => {
                    const rr = dns[`${type}_records`] || [];
                    return rr.length > 0 && (
                      <div key={type} className="mb-3">
                        <div className="text-[10px] text-mc-brand font-mono uppercase mb-1">{type.toUpperCase()} Records</div>
                        {rr.map((r: string, i: number) => <div key={i} className="text-xs text-mc-txt2 font-mono truncate">{typeof r === 'string' ? r : JSON.stringify(r)}</div>)}
                      </div>
                    );
                  })}
                </Card>
                {/* MX */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">MX Records {mx.provider && mx.provider !== 'Unknown' && <Badge severity="info">{mx.provider}</Badge>}</h3>
                  {(mx.records || dns.mx_records || []).map((r: any, i: number) => <div key={i} className="text-xs text-mc-txt2 font-mono">{typeof r === 'string' ? r : `${r.priority || ''} ${r.host || r}`}</div>)}
                </Card>
                {/* SPF */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">SPF Record {spf.exists && <Badge severity={spf.issues?.length ? 'medium' : 'low'}>Lookups: {spf.lookups || 0}/10</Badge>}</h3>
                  {spf.record ? <div className="text-xs text-mc-txt2 font-mono break-all">{spf.record}</div> : <div className="text-xs text-mc-rose">No SPF record found</div>}
                  {(spf.issues || []).map((iss: string, i: number) => <div key={i} className="text-[11px] text-mc-amber mt-1">⚠ {iss}</div>)}
                </Card>
                {/* DKIM */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">DKIM {dkim.exists && <Badge severity="low">Key: {dkim.key_length || '?'}-bit</Badge>}</h3>
                  {dkim.exists ? <div className="text-xs text-mc-txt2">Selectors found: {(dkim.selectors_found || []).join(', ')}</div> : <div className="text-xs text-mc-rose">No DKIM selector found</div>}
                  {(dkim.issues || []).map((iss: string, i: number) => <div key={i} className="text-[11px] text-mc-amber mt-1">⚠ {iss}</div>)}
                </Card>
                {/* DMARC */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">DMARC {dmarc.policy && <Badge severity={dmarc.policy === 'reject' ? 'low' : dmarc.policy === 'quarantine' ? 'medium' : 'high'}>p={dmarc.policy}</Badge>}</h3>
                  {dmarc.record ? <div className="text-xs text-mc-txt2 font-mono break-all">{dmarc.record}</div> : <div className="text-xs text-mc-rose">No DMARC record found</div>}
                  {(dmarc.issues || []).map((iss: string, i: number) => <div key={i} className="text-[11px] text-mc-amber mt-1">⚠ {iss}</div>)}
                </Card>
                {/* SMTP */}
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">SMTP Configuration {smtp.simulated && <Badge severity="info">Simulated</Badge>}</h3>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="text-mc-txt3">Open Relay</div><div className={smtp.relay_open ? 'text-mc-rose font-bold' : 'text-mc-emerald'}>{smtp.relay_open ? '⚠️ OPEN RELAY' : 'No ✓'}</div>
                    <div className="text-mc-txt3">STARTTLS</div><div className={smtp.starttls_supported ? 'text-mc-emerald' : 'text-mc-rose'}>{smtp.starttls_supported ? 'Supported ✓' : 'Not Supported ⚠'}</div>
                    {smtp.banner && <><div className="text-mc-txt3">Banner</div><div className="text-mc-txt font-mono text-[11px]">{smtp.banner}</div></>}
                  </div>
                  {smtp.log && smtp.log.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[10px] text-mc-txt3 uppercase font-semibold mb-2">Relay Test Log</div>
                      <div className="bg-mc-bg0 rounded-lg p-3 font-mono text-[11px] max-h-48 overflow-y-auto space-y-0.5">
                        {smtp.log.map((line: string, i: number) => (
                          <div key={i} className={
                            line.startsWith('S:') ? 'text-blue-400' :
                            line.startsWith('C:') ? 'text-emerald-400' :
                            line.includes('OPEN RELAY') ? 'text-red-400 font-bold' :
                            line.includes('rejected') ? 'text-orange-400' :
                            'text-mc-txt3'
                          }>{line}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  {smtp.relay_open && smtp.recommendations?.length > 0 && (
                    <div className="mt-3 space-y-1">
                      <div className="text-[10px] text-red-400 uppercase font-bold mb-2">⚠️ המלצות לתיקון</div>
                      {smtp.recommendations.map((r: string, i: number) => (
                        <div key={i} className="bg-red-500/5 border-l-2 border-red-500/40 rounded px-3 py-2 text-[12px] text-red-300">{r}</div>
                      ))}
                    </div>
                  )}
                  <div className="hidden">
                  </div>
                </Card>
              </div>
            )}

            {/* Tab 4: WHOIS */}
            {tab === 'whois' && (
              <Card className="p-4">
                {whois.status === 'limited' ? (
                  <div className="text-center py-8"><div className="text-mc-amber text-sm mb-1">⚠ מידע WHOIS מוגבל</div><div className="text-xs text-mc-txt3">Could not retrieve full WHOIS data</div></div>
                ) : (
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div><div className="text-mc-txt3 mb-1">Registrar</div><div className="text-white">{whois.registrar || 'Unknown'}</div></div>
                    <div><div className="text-mc-txt3 mb-1">Domain Status</div><div className="text-white font-mono text-[10px]">{whois.domain_status || 'N/A'}</div></div>
                    <div><div className="text-mc-txt3 mb-1">Created</div><div className="text-white">{whois.created_date ? new Date(whois.created_date).toLocaleDateString() : 'N/A'}</div></div>
                    <div><div className="text-mc-txt3 mb-1">Expires</div><div className="text-white">{whois.expiry_date ? new Date(whois.expiry_date).toLocaleDateString() : 'N/A'}</div></div>
                    <div><div className="text-mc-txt3 mb-1">Updated</div><div className="text-white">{whois.updated_date ? new Date(whois.updated_date).toLocaleDateString() : 'N/A'}</div></div>
                    <div><div className="text-mc-txt3 mb-1">Country</div><div className="text-white">{whois.country || 'N/A'}</div></div>
                  </div>
                )}
                {(whois.name_servers || []).length > 0 && (
                  <div className="mt-4 pt-3 border-t border-mc-cardBorder"><div className="text-[10px] text-mc-txt3 uppercase mb-2">Name Servers ({whois.name_servers.length})</div>
                    {whois.name_servers.map((ns: string, i: number) => <div key={i} className="text-xs text-mc-txt2 font-mono">{ns}</div>)}
                  </div>
                )}
              </Card>
            )}

            {/* Tab 5: Blacklist */}
            {tab === 'blacklist' && (
              <div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">{bl.total_ips || 0}</div><div className="text-[10px] text-mc-txt3">Total IPs</div></Card>
                  <Card className="p-4 text-center"><div className="text-2xl font-bold text-white">4</div><div className="text-[10px] text-mc-txt3">DNSBL Checked</div></Card>
                  <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-rose">{bl.listed_ips_count || 0}</div><div className="text-[10px] text-mc-txt3">Listed</div></Card>
                  <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-emerald">{bl.clean_ips_count || (bl.total_ips || 0) - (bl.listed_ips_count || 0)}</div><div className="text-[10px] text-mc-txt3">Clean</div></Card>
                </div>
                <Card className="p-4">
                  <h3 className="text-sm font-semibold text-white mb-3">IP Check Results</h3>
                  {(bl.ips_checked || []).map((ipCheck: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 py-1.5 text-xs">
                      {ipCheck.listed ? <AlertTriangle size={12} className="text-mc-rose" /> : <CheckCircle2 size={12} className="text-mc-emerald" />}
                      <span className="font-mono text-white">{ipCheck.ip}</span>
                      <span className={ipCheck.listed ? 'text-mc-rose' : 'text-mc-emerald'}>{ipCheck.listed ? 'Listed' : 'Clean'}</span>
                      {ipCheck.listed && ipCheck.lists?.map((l: any, j: number) => <Badge key={j} severity="high">{l.name}</Badge>)}
                    </div>
                  ))}
                  {(bl.ips_checked || []).length === 0 && <div className="text-xs text-mc-txt3">No IPs checked</div>}
                  {bl.listed_ips_count === 0 && (bl.ips_checked || []).length > 0 && (
                    <div className="mt-3 pt-3 border-t border-mc-cardBorder text-center"><CheckCircle2 size={16} className="text-mc-emerald mx-auto mb-1" /><div className="text-xs text-mc-emerald">All IPs are clean</div><div className="text-[10px] text-mc-txt3">No IPs found on major DNS block lists</div></div>
                  )}
                </Card>
              </div>
            )}

            {/* Tab 6: IP Reputation (AbuseIPDB) */}
            {tab === 'reputation' && (
              <Card className="p-4">
                {!abuse.configured && !abuse.available ? (
                  <div className="text-center py-8"><div className="text-mc-txt3 text-sm mb-1">⚙ AbuseIPDB Not Configured</div><div className="text-[11px] text-mc-txt3">Admin must set ABUSEIPDB_API_KEY in environment</div></div>
                ) : (
                  <div>
                    <div className="text-center mb-4">
                      <div className={`text-4xl font-bold ${(abuse.abuse_confidence_score || 0) < 25 ? 'text-mc-emerald' : (abuse.abuse_confidence_score || 0) < 75 ? 'text-mc-amber' : 'text-mc-rose'}`}>{abuse.abuse_confidence_score || 0}%</div>
                      <div className="text-xs text-mc-txt3">Abuse Confidence Score</div>
                      <div className={`text-sm mt-1 ${abuse.safe ? 'text-mc-emerald' : 'text-mc-rose'}`}>{abuse.safe ? '✓ Safe IP' : '⚠ Potentially Malicious'}</div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div><div className="text-mc-txt3">IP Address</div><div className="text-white font-mono">{abuse.ip_address || 'N/A'}</div></div>
                      <div><div className="text-mc-txt3">Country</div><div className="text-white">{abuse.country_name || 'N/A'}</div></div>
                      <div><div className="text-mc-txt3">ISP</div><div className="text-white">{abuse.isp || 'N/A'}</div></div>
                      <div><div className="text-mc-txt3">Usage Type</div><div className="text-white">{abuse.usage_type || 'N/A'}</div></div>
                      <div><div className="text-mc-txt3">Total Reports</div><div className="text-white">{abuse.total_reports || 0}</div></div>
                      <div><div className="text-mc-txt3">Distinct Reporters</div><div className="text-white">{abuse.num_distinct_users || 0}</div></div>
                    </div>
                  </div>
                )}
              </Card>
            )}

            {/* Tab 7: MXToolbox Links */}
            {tab === 'tools' && (
              <Card className="p-4 space-y-2">
                {Object.entries(mxLinks).length > 0 ? Object.entries(mxLinks).map(([key, url]: any) => (
                  <a key={key} href={url} target="_blank" rel="noopener" className="flex items-center gap-2 text-xs text-mc-brand hover:text-mc-brandLight transition py-2 px-3 rounded-lg hover:bg-mc-brand/5">
                    <ExternalLink size={13} />{key.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                  </a>
                )) : <div className="text-xs text-mc-txt3">No links available</div>}
              </Card>
            )}

            {/* Tab 8: Recommendations */}
            {tab === 'recommendations' && (
              <div className="space-y-2">
                {recs.map((r: string, i: number) => (
                  <Card key={i} className="px-4 py-3 flex items-start gap-2">
                    <CheckCircle2 size={14} className="text-mc-emerald mt-0.5 shrink-0" />
                    <span className="text-xs text-mc-txt2">{r}</span>
                  </Card>
                ))}
                {findings.map((f: any, i: number) => (
                  <Card key={`f-${i}`} className="px-4 py-3 flex items-start gap-2">
                    <AlertTriangle size={14} className={`${sevColor(f.severity).text} mt-0.5 shrink-0`} />
                    <div><div className="text-xs text-white font-medium">{f.title}</div><div className="text-[11px] text-mc-txt3">{f.description}</div></div>
                  </Card>
                ))}
                {recs.length === 0 && findings.length === 0 && <EmptyState title="No recommendations" subtitle="Your email security looks good!" />}
              </div>
            )}
          </div>
        )}

        {/* History */}
                {!scanId && !result && (
          <div className="max-w-[800px] mx-auto px-4 py-12 text-center">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">📧</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("SPF, DKIM & DMARC")}</h3>
                <p className="text-xs text-white/40">{t("SPF DKIM DMARC desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">🔒</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Blacklist & Reputation")}</h3>
                <p className="text-xs text-white/40">{t("Blacklist Reputation desc")}</p>
              </div>
              <div className="p-5 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-2xl mb-2">⚙️</div>
                <h3 className="text-sm font-semibold text-white mb-1">{t("Infrastructure Analysis")}</h3>
                <p className="text-xs text-white/40">{t("Infrastructure Analysis desc")}</p>
              </div>
            </div>
          </div>
        )}

        {!scanId && <ScanHistory type="email" onSelectScan={loadHistoryScan} />}
      </div>
    </div>
  );
}

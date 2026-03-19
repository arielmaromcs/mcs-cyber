import { useLang } from '../hooks/useLang';
import { useState, useEffect } from 'react';
import { Calendar, Plus, Play, Pause, Trash2, TestTube, Clock, Mail, Globe, Crosshair, X, Pencil, Zap } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Badge, Button, Tabs, Input, EmptyState, Spinner } from '../components/ui';

export default function Schedules() {
  const { t } = useLang();
  const [schedules, setSchedules] = useState<any>({ web: [], email: [], threat: [] });
  const [logs, setLogs] = useState<any[]>([]);
  const [tab, setTab] = useState('all');
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);

  // Create form
  const [cType, setCType] = useState('web');
  const [cTarget, setCTarget] = useState('');
  const [cFreq, setCFreq] = useState('weekly');
  const [cTime, setCTime] = useState('09:00');
  const [cEmails, setCEmails] = useState('');
  const [cDescription, setCDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [editSchedule, setEditSchedule] = useState<any>(null);
  const [runningId, setRunningId] = useState('');
  // Threat Intel advanced config
  const [cScanARecords, setCSlcanARecords] = useState(true);
  const [cScanMxRecords, setCScanMxRecords] = useState(true);
  const [cScanTxtRecords, setCScanTxtRecords] = useState(true);
  const [cProfile, setCProfile] = useState('baseline_syn_1000');
  const [cIncludeCve, setCIncludeCve] = useState(false);
  const [cEmailResults, setCEmailResults] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [s, l] = await Promise.all([api.listSchedules(), api.scheduleLogs()]);
      setSchedules(s || { web: [], email: [], threat: [] });
      setLogs(Array.isArray(l) ? l : l?.logs || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (editSchedule) {
      setCType(editSchedule._type || 'web');
      setCTarget(editSchedule.url || editSchedule.domain || editSchedule.target || '');
      setCFreq((editSchedule.frequency || 'weekly').toLowerCase());
      setCTime(editSchedule.startTime || editSchedule.start_time || '09:00');
      setCEmails((editSchedule.notifyEmails || editSchedule.notify_emails || []).join(', '));
    }
  }, [editSchedule]);

  const create = async () => {
    setCreating(true);
    try {
      const schedData: any = {
        target: cTarget, frequency: cFreq, start_time: cTime, description: cDescription || undefined,
        notify_emails: cEmails.split(',').map(e => e.trim()).filter(Boolean).slice(0, 5),
      };
      if (cType === 'threat') {
        schedData.nmap_config = {
          scan_a_records: cScanARecords,
          scan_mx_records: cScanMxRecords,
          scan_txt_records: cScanTxtRecords,
          profile: cProfile,
          include_cve_nse: cIncludeCve,
          email_results_only: cEmailResults && !cIncludeCve,
        };
      }
      await api.createSchedule(cType, schedData);
      setShowCreate(false); setCTarget(''); setCEmails(''); setCDescription('');
      load();
    } catch {}
    setCreating(false);
  };

  const toggle = async (type: string, id: string, currentActive: boolean) => {
    try { await api.toggleSchedule(type, id, currentActive); load(); } catch {}
  };

  const del = async (type: string, id: string) => {
    if (!confirm('Delete this schedule?')) return;
    try { await api.deleteSchedule(type, id); load(); } catch {}
  };

  const [testMsg, setTestMsg] = useState('');
  const [liveScan, setLiveScan] = useState<any>(null);

  const test = async (type: string, target: string) => {
    try {
      const r = await api.testSchedule(type, target);
      if (r?.scan_id) {
        setLiveScan({ id: r.scan_id, type, target, progress: 0, status: 'RUNNING', stage: 'Starting...' });
        // Poll for progress
        const poll = setInterval(async () => {
          try {
            let status: any;
            const authHeader = { 'Authorization': 'Bearer ' + localStorage.getItem('mc_token') };
            if (type === 'web') {
              status = await fetch('/api/web-scan/status/' + r.scan_id, { headers: authHeader }).then(r => r.json());
            } else if (type === 'email') {
              status = await fetch('/api/email-scan/status/' + r.scan_id, { headers: authHeader }).then(r => r.json());
            } else if (type === 'threat') {
              status = await fetch('/api/threat-intel/nmap-status/' + r.scan_id, { headers: authHeader }).then(r => r.json());
              if (status) {
                status.status = status.status || (status.progress >= 100 ? 'COMPLETED' : 'RUNNING');
                status.stage = status.stage || status.current_phase || 'Scanning ports...';
              }
            }
            if (status) {
              setLiveScan((prev: any) => prev ? { ...prev, progress: status.progress || 0, status: status.status, stage: status.stage || status.currentStage || 'Scanning...' } : null);
              if (status.status === 'COMPLETED' || status.status === 'FAILED') {
                clearInterval(poll);
                setTimeout(() => setLiveScan(null), 8000);
                load(); // refresh schedules
              }
            }
          } catch {}
        }, 2000);
      }
      setTestMsg('');
    } catch (e: any) {
      setTestMsg('Failed: ' + (e.message || 'unknown error'));
      setTimeout(() => setTestMsg(''), 5000);
    }
  };

  const allSchedules = [...(schedules.web || []).map((s: any) => ({ ...s, _type: 'web' })),
    ...(schedules.email || []).map((s: any) => ({ ...s, _type: 'email' })),
    ...(schedules.threat || []).map((s: any) => ({ ...s, _type: 'threat' }))];
  const filtered = tab === 'all' ? allSchedules : allSchedules.filter(s => s._type === tab);

  const TypeIcon = (t: string) => t === 'web' ? Globe : t === 'email' ? Mail : Crosshair;

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Calendar size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">{t("Scheduled Scans title")}</h1><p className="text-sm text-blue-100/60">{t("Automated recurring security scans")}</p></div>
          </div>
          <Button onClick={() => setShowCreate(true)}><Plus size={14} /> New Schedule</Button>
        </div>
      </div>

      <div className="max-w-[1100px] mx-auto px-4 py-6">
        {/* Create Dialog */}
        {showCreate && (
          <Card className="p-5 mb-5 border-mc-brand/20 animate-fadeIn">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">{editSchedule ? "Edit Schedule" : "Create Schedule"}</h3>
              <button onClick={() => setShowCreate(false)}><X size={14} className="text-mc-txt3" /></button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
              <div>
                <label className="text-[10px] text-mc-txt3 mb-1 block">Type</label>
                <select value={cType} onChange={e => setCType(e.target.value)} className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-2 py-1.5 text-xs text-mc-txt outline-none">
                  <option value="web">{t("Web")}</option><option value="email">{t("Email")}</option><option value="threat">{t("Port Exposure Scan")}</option>
                </select>
              </div>
              <Input label="Target" value={cTarget} onChange={(e: any) => setCTarget(e.target.value)} placeholder={cType === 'web' ? 'https://...' : 'domain.com'} />
              <div>
                <label className="text-[10px] text-mc-txt3 mb-1 block">{t("Frequency")}</label>
                <select value={cFreq} onChange={e => setCFreq(e.target.value)} className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-2 py-1.5 text-xs text-mc-txt outline-none">
                  <option value="daily">{t("Daily")}</option><option value="weekly">{t("Weekly")}</option><option value="monthly">{t("Monthly")}</option>
                </select>
              </div>
              <Input label="Start Time" type="time" value={cTime} onChange={(e: any) => setCTime(e.target.value)} />
            </div>
            <Input label="Notify Emails (comma-separated, max 5)" value={cEmails} onChange={(e: any) => setCEmails(e.target.value)} placeholder="user@example.com" />
            <Input label="Description (optional)" value={cDescription} onChange={(e: any) => setCDescription(e.target.value)} placeholder="e.g. Production server, Client XYZ" className="mt-3" />
            {/* Threat Intel Advanced Options */}
            {cType === 'threat' && (
              <div className="mt-4 space-y-4">
                {/* DNS Record Types */}
                <div>
                  <div className="text-xs font-semibold text-white mb-2">DNS Records to Resolve</div>
                  <div className="flex gap-3">
                    {[{ label: 'A Records (IPv4)', val: cScanARecords, set: setCSlcanARecords, color: 'blue' },
                      { label: 'MX Records (Mail)', val: cScanMxRecords, set: setCScanMxRecords, color: 'amber' },
                      { label: 'TXT Records (SPF)', val: cScanTxtRecords, set: setCScanTxtRecords, color: 'green' }]
                      .map(({ label, val, set, color }) => (
                        <label key={label} className={'flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition ' + (val ? 'border-' + color + '-500/30 bg-' + color + '-500/10' : 'border-white/10 bg-white/[0.02]')}>
                          <input type="checkbox" checked={val} onChange={e => set(e.target.checked)} className="w-3.5 h-3.5 rounded" />
                          <span className="text-xs text-white">{label}</span>
                        </label>
                      ))}
                  </div>
                </div>

                {/* Scan Profile */}
                <div>
                  <div className="text-xs font-semibold text-white mb-2">Scan Profile</div>
                  <div className="grid grid-cols-3 gap-3">
                    {[{ id: 'baseline_syn_1000', label: 'Quick Exposure', desc: 'SYN scan on top 1000 ports', time: '~30 sec', num: 1 },
                      { id: 'service_discovery', label: 'Service Discovery', desc: 'Service + version + OS detection', time: '~2-5 min', num: 2 },
                      { id: 'security_posture', label: 'Security Posture', desc: 'Deep scan + NSE scripts + CVE mapping', time: '~5-15 min', num: 3 }]
                      .map(p => (
                        <button key={p.id} onClick={() => setCProfile(p.id)}
                          className={'p-3 rounded-xl border text-left transition ' + (cProfile === p.id ? 'border-blue-500/50 bg-blue-500/10' : 'border-white/10 bg-white/[0.02] hover:border-white/20')}>
                          <div className="flex items-center gap-2 mb-1">
                            <div className={'w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ' + (cProfile === p.id ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/40')}>{p.num}</div>
                            <span className="text-xs font-semibold text-white">{p.label}</span>
                          </div>
                          <p className="text-[10px] text-white/40">{p.desc}</p>
                          <span className="text-[9px] text-white/25">{p.time}</span>
                        </button>
                      ))}
                  </div>
                </div>

                {/* Output Options */}
                <div>
                  <div className="text-xs font-semibold text-white mb-2">Output Options</div>
                  <div className="flex gap-3">
                    <label className={'flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition ' + (cIncludeCve ? 'border-rose-500/30 bg-rose-500/10' : 'border-white/10 bg-white/[0.02]')}>
                      <input type="checkbox" checked={cIncludeCve} onChange={e => setCIncludeCve(e.target.checked)} className="w-3.5 h-3.5 rounded" />
                      <span className="text-xs text-white">Include CVE + NSE Analysis</span>
                    </label>
                    <label className={'flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition ' + (cEmailResults ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-white/10 bg-white/[0.02]')}>
                      <input type="checkbox" checked={cEmailResults} onChange={e => setCEmailResults(e.target.checked)} className="w-3.5 h-3.5 rounded" />
                      <span className="text-xs text-white">Email ports summary only</span>
                    </label>
                  </div>
                </div>
              </div>
            )}

            <div className="flex gap-2 mt-3">
              <Button onClick={create} disabled={creating || !cTarget}>{creating ? <Spinner size={14} /> : editSchedule ? 'Update' : 'Create'}</Button>
              <Button variant="secondary" onClick={() => { setShowCreate(false); setEditSchedule(null); }}>{t("Cancel")}</Button>
            </div>
          </Card>
        )}

        <Tabs active={tab} onChange={setTab} tabs={[
          { key: 'all', label: t('All'), count: allSchedules.length },
          { key: 'web', label: t('Web'), count: (schedules.web || []).length },
          { key: 'email', label: t('Email'), count: (schedules.email || []).length },
          { key: 'threat', label: t('Port Exposure'), count: (schedules.threat || []).length },
          { key: 'logs', label: 'Execution Logs', count: logs.length },
        ]} />

        {/* Live Scan Progress */}
        {liveScan && (
          <div className="mb-4 p-4 rounded-xl bg-gradient-to-r from-blue-500/10 to-emerald-500/10 border border-blue-500/20 animate-fadeIn">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs font-semibold text-white">{liveScan.target}</span>
                <span className="text-[10px] text-white/40">{liveScan.type.toUpperCase()} scan</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-blue-400 font-mono">{liveScan.progress}%</span>
                <span className={'text-[10px] px-2 py-0.5 rounded-full ' + (liveScan.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400' : liveScan.status === 'FAILED' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400')}>{liveScan.status}</span>
              </div>
            </div>
            <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden mb-1">
              <div className="h-full rounded-full transition-all duration-500" style={{ width: liveScan.progress + '%', background: liveScan.status === 'COMPLETED' ? '#10b981' : liveScan.status === 'FAILED' ? '#ef4444' : 'linear-gradient(90deg, #3b82f6, #10b981)' }} />
            </div>
            <div className="text-[10px] text-white/30">{liveScan.stage}</div>
          </div>
        )}

        {testMsg && (
          <div className="mb-3 px-4 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 animate-fadeIn">
            {testMsg}
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-12"><Spinner size={24} className="text-mc-brand" /></div>
        ) : tab === 'logs' ? (
          <div className="space-y-1.5">
            {logs.length === 0 ? <EmptyState icon={Clock} title="No execution logs yet" /> :
              logs.map((l: any, i: number) => (
                <Card key={i} className="px-4 py-2.5 flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${l.status === 'success' ? 'bg-mc-emerald' : 'bg-mc-rose'}`} />
                  <span className="text-xs text-white font-mono">{l.target}</span>
                  <Badge severity={l.status === 'success' ? 'low' : 'critical'}>{l.status}</Badge>
                  <span className="text-[10px] text-mc-txt3 ml-auto">{l.executed_at || l.executedAt ? new Date(l.executed_at || l.executedAt).toLocaleString() : ''}</span>
                </Card>
              ))}
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.length === 0 ? <EmptyState icon={Calendar} title="No schedules" subtitle="Create one to get started" /> :
              filtered.map((s: any) => {
                const Icon = TypeIcon(s._type);
                return (
                  <Card key={s.id} className="px-4 py-3 flex items-center gap-3">
                    <Icon size={16} className="text-mc-brand shrink-0" />
                    <div className="flex-1 min-w-0">
                      {s.description && <div className="text-xs font-semibold text-white">{s.description}</div>}
                      <div className="text-sm font-medium text-mc-txt2 truncate">{s.url || s.domain || s.target}</div>
                      <div className="text-[10px] text-mc-txt3">{s.frequency} at {s.startTime || s.start_time || '09:00'} • {s.isActive || s.is_active ? 'Active' : 'Paused'}</div>
                    </div>
                    {s.lastScore != null && <span className="text-xs font-mono text-mc-brand">{s.lastScore || s.last_score}</span>}
                    <div className="flex gap-1">
                      <button onClick={() => { setEditSchedule(s); setShowCreate(true); }} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-blue-400 transition" title="Edit"><Pencil size={13} /></button>
                      <button onClick={() => toggle(s._type, s.id, s.isActive ?? s.is_active ?? true)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-brand transition" title={(s.isActive ?? s.is_active) ? 'Pause' : 'Resume'}>
                        {(s.isActive ?? s.is_active) ? <Pause size={13} /> : <Play size={13} />}
                      </button>
                      <button onClick={() => { test(s._type, s.url || s.domain || s.target); setRunningId(s.id); setTimeout(() => setRunningId(''), 3000); }} className={'p-1.5 rounded hover:bg-mc-bg2 transition ' + (runningId === s.id ? 'text-emerald-400 animate-pulse' : 'text-mc-txt3 hover:text-emerald-400')} title="Run Now"><Zap size={13} /></button>
                      <button onClick={() => del(s._type, s.id)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-rose transition" title="Delete"><Trash2 size={13} /></button>
                    </div>
                  </Card>
                );
              })}
          </div>
        )}
      </div>
    </div>
  );
}

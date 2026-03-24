import { useState, useEffect } from 'react';
import { Users, Plus, Pencil, Trash2, CheckCircle2, XCircle, Phone, Mail, Globe, Building, X, Save, Calendar, ChevronDown, ChevronUp, Zap } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Button, Input, Spinner, Badge } from '../components/ui';
import { useAuth } from '../hooks/useAuth';

const emptyForm = { name: '', domain: '', ip: '', office: '', contactName: '', contactPhone: '', contactEmail: '', serviceAgreement: false, notes: '' };

export default function Customers() {
  const { user } = useAuth();
  const [customers, setCustomers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [schedules, setSchedules] = useState<Record<string, any[]>>({});
  const [loadingSchedules, setLoadingSchedules] = useState<string | null>(null);
  const [showScheduleForm, setShowScheduleForm] = useState<string | null>(null);
  const [schedType, setSchedType] = useState('web');
  const [schedTarget, setSchedTarget] = useState('');
  const [schedFreq, setSchedFreq] = useState('weekly');
  const [schedTime, setSchedTime] = useState('09:00');
  const [schedEmails, setSchedEmails] = useState('');
  const [creatingSchedule, setCreatingSchedule] = useState(false);
  const [runningId, setRunningId] = useState('');

  const load = async () => {
    setLoading(true);
    try { setCustomers(await (api as any).getClients() || []); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const loadSchedules = async (customerId: string, domain: string) => {
    setLoadingSchedules(customerId);
    try {
      const s = await (api as any).getClientSchedules(customerId);
      setSchedules(prev => ({ ...prev, [customerId]: s || [] }));
    } catch { setSchedules(prev => ({ ...prev, [customerId]: [] })); }
    setLoadingSchedules(null);
  };

  const toggleExpand = (c: any) => {
    if (expandedId === c.id) { setExpandedId(null); return; }
    setExpandedId(c.id);
    loadSchedules(c.id, c.domain);
    setSchedTarget(c.domain || c.ip || '');
    setSchedEmails(c.contact_email || '');
  };

  const openAdd = () => { setForm(emptyForm); setEditId(null); setShowForm(true); };
  const openEdit = (c: any) => {
    setForm({ name: c.name || '', domain: c.domain || '', ip: c.ip || '', office: c.office || '', contactName: c.contact_name || '', contactPhone: c.contact_phone || '', contactEmail: c.contact_email || '', serviceAgreement: c.service_agreement || false, notes: c.notes || '' });
    setEditId(c.id); setShowForm(true);
  };

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      if (editId) await (api as any).updateClient(editId, form);
      else await (api as any).createClient(form);
      setShowForm(false); load();
    } catch {}
    setSaving(false);
  };

  const del = async (id: string) => {
    if (!confirm('מחק לקוח זה?')) return;
    try { await (api as any).deleteClient(id); load(); } catch {}
  };

  const createSchedule = async (customerId: string) => {
    setCreatingSchedule(true);
    try {
      await api.createSchedule(schedType, {
        target: schedTarget, frequency: schedFreq, start_time: schedTime,
        notify_emails: schedEmails.split(',').map((e: string) => e.trim()).filter(Boolean),
        customer_id: customerId,
      });
      setShowScheduleForm(null);
      loadSchedules(customerId, schedTarget);
    } catch {}
    setCreatingSchedule(false);
  };

  const runNow = async (s: any, customerId: string) => {
    setRunningId(s.id);
    try {
      await (api as any).runScheduleNow(s._type || 'threat', s.id);
      setTimeout(() => { setRunningId(''); loadSchedules(customerId, ''); }, 5000);
    } catch { setRunningId(''); }
  };

  const delSchedule = async (s: any, customerId: string) => {
    if (!confirm('מחק סריקה זו?')) return;
    try { await api.deleteSchedule(s._type || 'threat', s.id); loadSchedules(customerId, ''); } catch {}
  };

  const filtered = customers.filter(c => !search ||
    c.name?.toLowerCase().includes(search.toLowerCase()) ||
    c.domain?.includes(search) ||
    c.contact_name?.toLowerCase().includes(search.toLowerCase()));

  const typeIcon = (t: string) => t === 'web' ? '🌐' : t === 'email' ? '✉️' : t === 'full' ? '🛡' : '🎯';
  const typeLabel = (t: string) => t === 'web' ? 'Web' : t === 'email' ? 'Email' : t === 'full' ? 'Full Scan' : 'Port Scan';

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[1000px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Users size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">Customers</h1><p className="text-sm text-blue-100/60">ניהול לקוחות וסריקות</p></div>
          </div>
          <Button onClick={openAdd}><Plus size={14} /> הוסף לקוח</Button>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto px-4 py-6">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-3 mb-5">
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-brand font-mono">{customers.length}</div><div className="text-[10px] text-mc-txt3">סה"כ לקוחות</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-emerald-400 font-mono">{customers.filter(c => c.service_agreement).length}</div><div className="text-[10px] text-mc-txt3">עם הסכם</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-amber-400 font-mono">{customers.filter(c => !c.service_agreement).length}</div><div className="text-[10px] text-mc-txt3">ללא הסכם</div></Card>
        </div>

        <Input placeholder="חיפוש לקוח..." value={search} onChange={(e: any) => setSearch(e.target.value)} className="mb-4" />

        {/* Add/Edit Modal */}
        {showForm && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-mc-bg1 border border-mc-cardBorder rounded-2xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-white">{editId ? 'ערוך לקוח' : 'הוסף לקוח חדש'}</h3>
                <button onClick={() => setShowForm(false)}><X size={16} className="text-mc-txt3" /></button>
              </div>
              <div className="space-y-3">
                <Input label="שם לקוח *" value={form.name} onChange={(e: any) => setForm({...form, name: e.target.value})} placeholder="שם החברה" />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="דומיין" value={form.domain} onChange={(e: any) => setForm({...form, domain: e.target.value})} placeholder="example.com" />
                  <Input label="IP משרד" value={form.ip} onChange={(e: any) => setForm({...form, ip: e.target.value})} placeholder="1.2.3.4" />
                </div>
                <Input label="משרד / מיקום" value={form.office} onChange={(e: any) => setForm({...form, office: e.target.value})} placeholder="תל אביב" />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="איש קשר" value={form.contactName} onChange={(e: any) => setForm({...form, contactName: e.target.value})} placeholder="שם מלא" />
                  <Input label="טלפון" value={form.contactPhone} onChange={(e: any) => setForm({...form, contactPhone: e.target.value})} placeholder="050-0000000" />
                </div>
                <Input label="אימייל איש קשר" value={form.contactEmail} onChange={(e: any) => setForm({...form, contactEmail: e.target.value})} placeholder="contact@example.com" />
                <div>
                  <label className="text-[10px] text-mc-txt3 mb-1 block">הערות</label>
                  <textarea value={form.notes} onChange={(e: any) => setForm({...form, notes: e.target.value})}
                    className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-3 py-2 text-xs text-mc-txt outline-none resize-none h-20" />
                </div>
                <label className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-mc-cardBorder bg-mc-bg2 cursor-pointer">
                  <input type="checkbox" checked={form.serviceAgreement} onChange={(e) => setForm({...form, serviceAgreement: e.target.checked})} className="w-4 h-4 rounded" />
                  <div><div className="text-xs font-medium text-white">הסכם שירות</div></div>
                  {form.serviceAgreement ? <CheckCircle2 size={16} className="text-emerald-400 ml-auto" /> : <XCircle size={16} className="text-mc-txt3 ml-auto" />}
                </label>
              </div>
              <div className="flex gap-2 mt-5">
                <Button onClick={save} disabled={saving || !form.name}>{saving ? <Spinner size={14} /> : <><Save size={14} /> שמור</>}</Button>
                <Button variant="secondary" onClick={() => setShowForm(false)}>ביטול</Button>
              </div>
            </div>
          </div>
        )}

        {/* Customer List */}
        {loading ? <div className="flex justify-center py-12"><Spinner size={24} className="text-mc-brand" /></div> : (
          <div className="space-y-3">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16">
                <Users size={40} className="text-white/20 mb-4" />
                <div className="text-lg font-semibold text-white mb-2">אין לקוחות</div>
                <div className="text-sm text-white/50">לחץ "הוסף לקוח" להתחלה</div>
              </div>
            ) : filtered.map((c: any) => (
              <div key={c.id} className="bg-mc-card border border-mc-cardBorder rounded-xl overflow-hidden">
                {/* Customer header */}
                <div className="p-4 flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-mc-brand/15 flex items-center justify-center text-sm font-bold text-mc-brand shrink-0">
                    {c.name?.[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-white">{c.name}</span>
                      {c.service_agreement
                        ? <span className="text-[9px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 font-semibold">✓ הסכם</span>
                        : <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/20 font-semibold">ללא הסכם</span>}
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                      {c.domain && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Globe size={10} /> {c.domain}</span>}
                      {c.ip && <span className="flex items-center gap-1 text-[11px] text-mc-txt3 font-mono">IP: {c.ip}</span>}
                      {c.office && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Building size={10} /> {c.office}</span>}
                      {c.contact_name && <span className="flex items-center gap-1 text-[11px] text-mc-txt3">{c.contact_name}</span>}
                      {c.contact_phone && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Phone size={10} /> {c.contact_phone}</span>}
                      {c.contact_email && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Mail size={10} /> {c.contact_email}</span>}
                    </div>
                  </div>
                  <div className="flex gap-1 shrink-0 items-center">
                    <button onClick={() => toggleExpand(c)}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-mc-brand/10 border border-mc-brand/20 text-mc-brand text-[11px] font-medium hover:bg-mc-brand/20 transition">
                      <Calendar size={12} />
                      סריקות
                      {expandedId === c.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </button>
                    <button onClick={() => openEdit(c)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-brand transition"><Pencil size={13} /></button>
                    <button onClick={() => del(c.id)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-rose transition"><Trash2 size={13} /></button>
                  </div>
                </div>

                {/* Schedules panel */}
                {expandedId === c.id && (
                  <div className="border-t border-mc-cardBorder bg-mc-bg2 p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="text-xs font-semibold text-white">סריקות מתוזמנות</div>
                      <button onClick={() => setShowScheduleForm(showScheduleForm === c.id ? null : c.id)}
                        className="flex items-center gap-1 px-2 py-1 rounded-lg bg-mc-brand/15 border border-mc-brand/25 text-mc-brand text-[11px] hover:bg-mc-brand/25 transition">
                        <Plus size={11} /> הוסף סריקה
                      </button>
                    </div>

                    {/* Add schedule form */}
                    {showScheduleForm === c.id && (
                      <div className="bg-mc-bg1 border border-mc-cardBorder rounded-xl p-4 mb-3">
                        <div className="grid grid-cols-2 gap-2 mb-2">
                          <div>
                            <label className="text-[10px] text-mc-txt3 mb-1 block">סוג</label>
                            <select value={schedType} onChange={e => setSchedType(e.target.value)}
                              className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-2 py-1.5 text-xs text-mc-txt outline-none">
                              <option value="web">🌐 Web</option>
                              <option value="email">✉️ Email</option>
                              <option value="threat">🎯 Port Scan</option>
                              <option value="full">🛡 Full Scan</option>
                            </select>
                          </div>
                          <Input label="Target" value={schedTarget} onChange={(e: any) => setSchedTarget(e.target.value)} placeholder={c.domain || c.ip || ''} />
                          <div>
                            <label className="text-[10px] text-mc-txt3 mb-1 block">תדירות</label>
                            <select value={schedFreq} onChange={e => setSchedFreq(e.target.value)}
                              className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-2 py-1.5 text-xs text-mc-txt outline-none">
                              <option value="daily">יומי</option>
                              <option value="weekly">שבועי</option>
                              <option value="monthly">חודשי</option>
                            </select>
                          </div>
                          <Input label="שעה" type="time" value={schedTime} onChange={(e: any) => setSchedTime(e.target.value)} />
                        </div>
                        <Input label="אימיילים לדיווח" value={schedEmails} onChange={(e: any) => setSchedEmails(e.target.value)} placeholder={c.contact_email || 'user@example.com'} className="mb-2" />
                        <div className="flex gap-2">
                          <Button onClick={() => createSchedule(c.id)} disabled={creatingSchedule || !schedTarget}>
                            {creatingSchedule ? <Spinner size={12} /> : <><Plus size={12} /> צור סריקה</>}
                          </Button>
                          <Button variant="secondary" onClick={() => setShowScheduleForm(null)}>ביטול</Button>
                        </div>
                      </div>
                    )}

                    {/* Schedules list */}
                    {loadingSchedules === c.id ? (
                      <div className="flex justify-center py-4"><Spinner size={16} className="text-mc-brand" /></div>
                    ) : (schedules[c.id] || []).length === 0 ? (
                      <div className="text-center py-4 text-[11px] text-mc-txt3">אין סריקות מוגדרות — לחץ "הוסף סריקה"</div>
                    ) : (
                      <div className="space-y-2">
                        {(schedules[c.id] || []).map((s: any) => (
                          <div key={s.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-mc-cardBorder bg-mc-bg1">
                            <span className="text-base">{typeIcon(s._type)}</span>
                            <div className="flex-1 min-w-0">
                              <div className="text-xs font-medium text-white">{typeLabel(s._type)} — {s.url || s.domain || s.target}</div>
                              <div className="text-[10px] text-mc-txt3">{s.frequency} at {s.start_time || s.startTime || '09:00'} · {s.is_active || s.isActive ? 'פעיל' : 'מושהה'}</div>
                            </div>
                            <div className="flex gap-1">
                              <button onClick={() => runNow(s, c.id)}
                                className={'p-1.5 rounded hover:bg-mc-bg2 transition ' + (runningId === s.id ? 'text-emerald-400 animate-pulse' : 'text-mc-txt3 hover:text-emerald-400')}
                                title="הפעל עכשיו"><Zap size={13} /></button>
                              <button onClick={() => delSchedule(s, c.id)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-rose transition"><Trash2 size={13} /></button>
                            </div>
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

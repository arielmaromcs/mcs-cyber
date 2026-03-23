import { useState, useEffect } from 'react';
import { Users, Plus, Pencil, Trash2, CheckCircle2, XCircle, Phone, Mail, Globe, Building, X, Save } from 'lucide-react';
import { api } from '../lib/api';
import { Card, Button, Input, Spinner } from '../components/ui';
import { useAuth } from '../hooks/useAuth';

const emptyForm = { name: '', domain: '', ip: '', office: '', contactName: '', contactPhone: '', contactEmail: '', serviceAgreement: false, notes: '' };

export default function Clients() {
  const { user } = useAuth();
  const [clients, setClients] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState('');

  const load = async () => {
    setLoading(true);
    try { setClients(await (api as any).getClients() || []); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

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
    if (!confirm('Delete this client?')) return;
    try { await (api as any).deleteClient(id); load(); } catch {}
  };

  const filtered = clients.filter(c => !search || c.name?.toLowerCase().includes(search.toLowerCase()) || c.domain?.includes(search) || c.contact_name?.toLowerCase().includes(search.toLowerCase()));

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[1000px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Users size={20} className="text-white" /></div>
            <div><h1 className="text-2xl font-bold text-white">Clients</h1><p className="text-sm text-blue-100/60">Manage your clients and service agreements</p></div>
          </div>
          <Button onClick={openAdd}><Plus size={14} /> Add Client</Button>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto px-4 py-6">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-3 mb-5">
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-brand font-mono">{clients.length}</div><div className="text-[10px] text-mc-txt3">Total Clients</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-emerald-400 font-mono">{clients.filter(c => c.service_agreement).length}</div><div className="text-[10px] text-mc-txt3">With Agreement</div></Card>
          <Card className="p-4 text-center"><div className="text-2xl font-bold text-amber-400 font-mono">{clients.filter(c => !c.service_agreement).length}</div><div className="text-[10px] text-mc-txt3">No Agreement</div></Card>
        </div>

        {/* Search */}
        <Input placeholder="Search clients..." value={search} onChange={(e: any) => setSearch(e.target.value)} className="mb-4" />

        {/* Form Modal */}
        {showForm && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-mc-bg1 border border-mc-cardBorder rounded-2xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-white">{editId ? 'Edit Client' : 'Add New Client'}</h3>
                <button onClick={() => setShowForm(false)}><X size={16} className="text-mc-txt3" /></button>
              </div>
              <div className="space-y-3">
                <Input label="Client Name *" value={form.name} onChange={(e: any) => setForm({...form, name: e.target.value})} placeholder="Company Name" />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="Domain" value={form.domain} onChange={(e: any) => setForm({...form, domain: e.target.value})} placeholder="example.com" />
                  <Input label="IP Address" value={form.ip} onChange={(e: any) => setForm({...form, ip: e.target.value})} placeholder="1.2.3.4" />
                </div>
                <Input label="Office / Location" value={form.office} onChange={(e: any) => setForm({...form, office: e.target.value})} placeholder="Tel Aviv" />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="Contact Name" value={form.contactName} onChange={(e: any) => setForm({...form, contactName: e.target.value})} placeholder="John Doe" />
                  <Input label="Phone" value={form.contactPhone} onChange={(e: any) => setForm({...form, contactPhone: e.target.value})} placeholder="+972-50-000-0000" />
                </div>
                <Input label="Contact Email" value={form.contactEmail} onChange={(e: any) => setForm({...form, contactEmail: e.target.value})} placeholder="contact@example.com" />
                <div>
                  <label className="text-[10px] text-mc-txt3 mb-1 block">Notes</label>
                  <textarea value={form.notes} onChange={(e: any) => setForm({...form, notes: e.target.value})}
                    className="w-full bg-mc-bg2 border border-mc-cardBorder rounded-lg px-3 py-2 text-xs text-mc-txt outline-none resize-none h-20" placeholder="Additional notes..." />
                </div>
                <label className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-mc-cardBorder bg-mc-bg2 cursor-pointer">
                  <input type="checkbox" checked={form.serviceAgreement} onChange={(e) => setForm({...form, serviceAgreement: e.target.checked})} className="w-4 h-4 rounded" />
                  <div>
                    <div className="text-xs font-medium text-white">Service Agreement</div>
                    <div className="text-[10px] text-mc-txt3">Client has an active service agreement</div>
                  </div>
                  {form.serviceAgreement ? <CheckCircle2 size={16} className="text-emerald-400 ml-auto" /> : <XCircle size={16} className="text-mc-txt3 ml-auto" />}
                </label>
              </div>
              <div className="flex gap-2 mt-5">
                <Button onClick={save} disabled={saving || !form.name}>{saving ? <Spinner size={14} /> : <><Save size={14} /> Save</>}</Button>
                <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
              </div>
            </div>
          </div>
        )}

        {/* Client List */}
        {loading ? <div className="flex justify-center py-12"><Spinner size={24} className="text-mc-brand" /></div> : (
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16">
                <Users size={40} className="text-white/20 mb-4" />
                <div className="text-lg font-semibold text-white mb-2">No clients yet</div>
                <div className="text-sm text-white/50">Click "Add Client" to get started</div>
              </div>
            ) : filtered.map((c: any) => (
              <Card key={c.id} className="p-4">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-mc-brand/15 flex items-center justify-center text-sm font-bold text-mc-brand shrink-0">
                    {c.name?.[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-white">{c.name}</span>
                      {c.service_agreement
                        ? <span className="text-[9px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 font-semibold">✓ Agreement</span>
                        : <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/20 font-semibold">No Agreement</span>}
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                      {c.domain && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Globe size={10} /> {c.domain}</span>}
                      {c.ip && <span className="flex items-center gap-1 text-[11px] text-mc-txt3 font-mono">IP: {c.ip}</span>}
                      {c.office && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Building size={10} /> {c.office}</span>}
                      {c.contact_name && <span className="flex items-center gap-1 text-[11px] text-mc-txt3">{c.contact_name}</span>}
                      {c.contact_phone && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Phone size={10} /> {c.contact_phone}</span>}
                      {c.contact_email && <span className="flex items-center gap-1 text-[11px] text-mc-txt3"><Mail size={10} /> {c.contact_email}</span>}
                    </div>
                    {c.notes && <div className="text-[10px] text-mc-txt3 mt-1 italic">{c.notes}</div>}
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <button onClick={() => openEdit(c)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-brand transition"><Pencil size={13} /></button>
                    <button onClick={() => del(c.id)} className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-rose transition"><Trash2 size={13} /></button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

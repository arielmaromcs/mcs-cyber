import { useLang } from '../hooks/useLang';
import { useState, useEffect } from 'react';
import { Info, Settings, Trash2, Plus, CheckCircle2, Send, Shield } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { Card, Button, Tabs, Input, Spinner } from '../components/ui';

export default function Admin() {
  const { t } = useLang();
  const { user } = useAuth();
  const [tab, setTab] = useState('users');
  const [users, setUsers] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('basic_scans');
  const [inviting, setInviting] = useState(false);
  const [emailProvider, setEmailProvider] = useState('smtp');
  const [es, setEs] = useState<any>({});
  const [verified, setVerified] = useState(false);
  const [emailMsg, setEmailMsg] = useState('');
  const [busy, setBusy] = useState('');

  useEffect(() => { loadAll(); }, []);
  const loadAll = async () => {
    setLoading(true);
    try { const [u, s] = await Promise.all([api.getUsers(), api.adminStats()]); setUsers(Array.isArray(u) ? u : u?.users || []); setStats(s || {}); } catch {}
    try { const d = await api.emailSettings('get'); if (d?.settings) { setEs(d.settings); setEmailProvider(d.settings.provider || 'smtp'); } } catch {}
    setLoading(false);
  };

  const invite = async () => { setInviting(true); try { await api.inviteUser(inviteEmail, inviteRole); setInviteEmail(''); loadAll(); } catch {} setInviting(false); };
  const updateU = async (id: string, data: any) => { try { await api.updateUser(id, data); loadAll(); } catch {} };
  const delU = async (id: string) => { if (confirm('Delete?')) { try { await api.deleteUser(id); loadAll(); } catch {} } };

  const doEmail = async (action: string) => {
    setBusy(action); setEmailMsg('');
    try {
      const d = await api.emailSettings(action, emailProvider, { ...es, provider: emailProvider });
      if (action === 'verify') setVerified(!!d.success);
      // save returns the record (has id), verify/test returns {success}
      const ok = d.success || d.id;
      setEmailMsg(ok ? `✅ ${action} succeeded` : `❌ ${action} failed: ${d.message || d.error || 'unknown'}`);
    } catch (e: any) { setEmailMsg(`❌ ${e.message}`); }
    setBusy('');
  };

  if (user?.role !== 'ADMIN') return (
    <div className="flex items-center justify-center min-h-[60vh]"><Card className="p-8 text-center"><Shield size={32} className="text-mc-rose mx-auto mb-3" /><div className="text-sm text-mc-txt2">Admin access required</div></Card></div>
  );

  const filtered = users.filter(u => !search || (u.email || '').includes(search) || (u.fullName || u.full_name || '').includes(search));

  return (
    <div>
      <div className="hero-bg py-10 px-4"><div className="max-w-[900px] mx-auto flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center"><Settings size={20} className="text-white" /></div>
        <div><h1 className="text-2xl font-bold text-white">Admin Panel</h1><p className="text-sm text-blue-100/60">User management & system configuration</p></div>
      </div></div>

      <div className="max-w-[1100px] mx-auto px-4 py-6">
        <Tabs active={tab} onChange={setTab} tabs={[{ key: 'users', label: t('Users') }, { key: 'email', label: t('Email Settings') }]} />

        {tab === 'users' && (
          <div>
            <div className="grid grid-cols-3 gap-3 mb-5">
              <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-brand font-mono">{users.length}</div><div className="text-[10px] text-mc-txt3">Total</div></Card>
              <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-amber font-mono">{users.filter(u => u.role === 'ADMIN').length}</div><div className="text-[10px] text-mc-txt3">Admins</div></Card>
              <Card className="p-4 text-center"><div className="text-2xl font-bold text-mc-emerald font-mono">{users.filter(u => u.role !== 'ADMIN').length}</div><div className="text-[10px] text-mc-txt3">Regular</div></Card>
            </div>

            <Card className="p-4 mb-4 flex items-end gap-3 flex-wrap">
              <div className="flex-1 min-w-[200px]"><Input label="Invite Email" value={inviteEmail} onChange={(e: any) => setInviteEmail(e.target.value)} placeholder="user@example.com" /></div>
              <div><label className="text-[10px] text-mc-txt3 mb-1 block">Role</label>
                <select value={inviteRole} onChange={e => setInviteRole(e.target.value)} className="bg-mc-bg2 border border-mc-cardBorder rounded-lg px-2 py-2 text-xs text-mc-txt outline-none">
                  <option value="basic_scans">Basic</option><option value="full_scans">Full</option><option value="admin">Admin</option>
                </select></div>
              <Button onClick={invite} disabled={inviting || !inviteEmail}>{inviting ? <Spinner size={14} /> : <><Plus size={14} /> Invite</>}</Button>
            </Card>

            <Input placeholder="Search users..." value={search} onChange={(e: any) => setSearch(e.target.value)} className="mb-3" />

            {loading ? <div className="flex justify-center py-8"><Spinner size={20} className="text-mc-brand" /></div> : (
              <div className="space-y-1.5">
                {filtered.map((u: any) => (
                  <Card key={u.id} className="px-4 py-3 flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-mc-brand/15 flex items-center justify-center text-[11px] font-bold text-mc-brand">
                      {(u.fullName || u.full_name || u.email)?.[0]?.toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-white truncate">{u.fullName || u.full_name || u.email}</div>
                      <div className="text-[10px] text-mc-txt3">{u.email}</div>
                    </div>
                    <select value={u.role} onChange={e => updateU(u.id, { role: e.target.value })}
                      className="bg-mc-bg2 border border-mc-cardBorder rounded px-2 py-1 text-[10px] text-mc-txt outline-none">
                      <option value="BASIC_SCANS">Basic</option><option value="FULL_SCANS">Full</option><option value="ADMIN">Admin</option>
                    </select>
                    <div className="text-xs text-mc-txt3 w-20 text-center">
                      {u.role === 'ADMIN' ? '∞' : (u.scansRemaining ?? u.scans_remaining ?? 0)} scans
                    </div>
                    <button onClick={() => delU(u.id)} disabled={u.role === 'ADMIN'}
                      className="p-1.5 rounded hover:bg-mc-bg2 text-mc-txt3 hover:text-mc-rose transition disabled:opacity-20"><Trash2 size={13} /></button>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'email' && (
          <div className="space-y-4">
            <div className="flex gap-2 mb-4">
              {['smtp', 'microsoft_graph'].map(p => (
                <button key={p} onClick={() => setEmailProvider(p)}
                  className={`px-4 py-2 rounded-lg text-xs font-medium transition ${emailProvider === p ? 'bg-mc-brand/15 text-mc-brand border border-mc-brand/25' : 'bg-mc-bg2 text-mc-txt3 border border-mc-cardBorder hover:text-mc-txt2'}`}>
                  {p === 'smtp' ? 'SMTP' : 'Microsoft Graph'}
                </button>
              ))}
            </div>

            <Card className="p-4 space-y-3">
              {emailProvider === 'smtp' ? (
                <div className="grid grid-cols-2 gap-3">
                  <Input label="SMTP Host" value={es.smtp_host || es.smtpHost || ''} onChange={(e: any) => setEs({ ...es, smtp_host: e.target.value })} placeholder="smtp.gmail.com" />
                  <Input label="SMTP Port" type="number" value={es.smtp_port || es.smtpPort || 587} onChange={(e: any) => setEs({ ...es, smtp_port: parseInt(e.target.value) })} />
                  <Input label="Username" value={es.smtp_user || es.smtpUser || ''} onChange={(e: any) => setEs({ ...es, smtp_user: e.target.value })} />
                  <Input label="Password" type="password" value={es.smtp_password || es.smtpPassword || ''} onChange={(e: any) => setEs({ ...es, smtp_password: e.target.value })} />
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3">
                  <Input label="Tenant ID" value={es.ms_tenant_id || es.msTenantId || ''} onChange={(e: any) => setEs({ ...es, ms_tenant_id: e.target.value })} />
                  <Input label="Client ID" value={es.ms_client_id || es.msClientId || ''} onChange={(e: any) => setEs({ ...es, ms_client_id: e.target.value })} />
                  <Input label="Client Secret" type="password" value={es.ms_client_secret || es.msClientSecret || ''} onChange={(e: any) => setEs({ ...es, ms_client_secret: e.target.value })} />
                </div>
              )}
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-mc-cardBorder">
                <Input label="From Email" value={es.from_email || es.fromEmail || ''} onChange={(e: any) => setEs({ ...es, from_email: e.target.value })} placeholder="noreply@..." />
                <Input label="From Name" value={es.from_name || es.fromName || ''} onChange={(e: any) => setEs({ ...es, from_name: e.target.value })} placeholder="M-Challenge" />
                <Input label="Reply-To" value={es.reply_to || es.replyTo || ''} onChange={(e: any) => setEs({ ...es, reply_to: e.target.value })} />
                <Input label="Test Email" value={es.test_email || es.testEmail || ''} onChange={(e: any) => setEs({ ...es, test_email: e.target.value })} />
              </div>
            </Card>

            <div className="flex gap-2">
              <Button onClick={() => doEmail('verify')} disabled={busy === 'verify'}>{busy === 'verify' ? <Spinner size={14} /> : <><CheckCircle2 size={14} /> Verify</>}</Button>
              <Button onClick={() => doEmail('save')} disabled={busy === 'save' || !verified} variant="secondary">{busy === 'save' ? <Spinner size={14} /> : 'Save Settings'}</Button>
              <Button onClick={() => doEmail('test')} disabled={busy === 'test'} variant="ghost"><Send size={14} /> Send Test</Button>
            </div>
            {emailMsg && <div className={`text-xs ${emailMsg.startsWith('✅') ? 'text-mc-emerald' : 'text-mc-rose'}`}>{emailMsg}</div>}

            {/* Setup Guide */}
            <Card className="p-5 mt-4">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2"><Info size={15} className="text-mc-brand" /> {emailProvider === 'smtp' ? 'SMTP Setup Guide' : 'Microsoft 365 Setup Guide'}</h3>

              {emailProvider === 'smtp' ? (
                <div className="space-y-4">
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">1</div>
                    <div><div className="text-xs font-semibold text-white">Enable App Password or SMTP Access</div>
                    <p className="text-[11px] text-white/40 mt-0.5"><strong className="text-white/60">Gmail:</strong> Go to myaccount.google.com &rarr; Security &rarr; 2-Step Verification &rarr; App Passwords &rarr; Create for "Mail"<br/>
                    <strong className="text-white/60">Outlook:</strong> Use your regular password with smtp.office365.com<br/>
                    <strong className="text-white/60">Yahoo:</strong> Go to Account Security &rarr; Generate App Password</p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">2</div>
                    <div><div className="text-xs font-semibold text-white">Fill in SMTP Server Details</div>
                    <div className="mt-1 rounded-lg bg-white/[0.03] border border-white/5 overflow-hidden">
                      <table className="w-full text-[11px]">
                        <thead><tr className="border-b border-white/5"><th className="px-3 py-1.5 text-left text-white/30 font-medium">Provider</th><th className="px-3 py-1.5 text-left text-white/30">Host</th><th className="px-3 py-1.5 text-left text-white/30">Port</th><th className="px-3 py-1.5 text-left text-white/30">Security</th></tr></thead>
                        <tbody>
                          <tr className="border-b border-white/5"><td className="px-3 py-1.5 text-white">Gmail</td><td className="px-3 py-1.5 text-blue-400 font-mono">smtp.gmail.com</td><td className="px-3 py-1.5 text-white/60">587</td><td className="px-3 py-1.5 text-white/60">STARTTLS</td></tr>
                          <tr className="border-b border-white/5"><td className="px-3 py-1.5 text-white">Outlook/365</td><td className="px-3 py-1.5 text-blue-400 font-mono">smtp.office365.com</td><td className="px-3 py-1.5 text-white/60">587</td><td className="px-3 py-1.5 text-white/60">STARTTLS</td></tr>
                          <tr><td className="px-3 py-1.5 text-white">Yahoo</td><td className="px-3 py-1.5 text-blue-400 font-mono">smtp.mail.yahoo.com</td><td className="px-3 py-1.5 text-white/60">587</td><td className="px-3 py-1.5 text-white/60">STARTTLS</td></tr>
                        </tbody>
                      </table>
                    </div></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">3</div>
                    <div><div className="text-xs font-semibold text-white">Set Sender Identity</div>
                    <p className="text-[11px] text-white/40 mt-0.5">Enter the <strong className="text-white/60">From Email</strong> (must match or be an alias of the SMTP account) and <strong className="text-white/60">From Name</strong> that recipients will see.</p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-emerald-500/15 flex items-center justify-center text-[11px] font-bold text-emerald-400 shrink-0">4</div>
                    <div><div className="text-xs font-semibold text-white">Verify, Save &amp; Test</div>
                    <p className="text-[11px] text-white/40 mt-0.5">Click <strong className="text-blue-400">{t("Verify")}</strong> to test SMTP connection &rarr; <strong className="text-blue-400">{t("Save Settings")}</strong> to store &rarr; <strong className="text-blue-400">{t("Send Test")}</strong> to confirm delivery. Check spam folder if not received.</p></div>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">1</div>
                    <div><div className="text-xs font-semibold text-white">Register App in Azure Portal</div>
                    <p className="text-[11px] text-white/40 mt-0.5">Go to <strong className="text-blue-400">portal.azure.com</strong> &rarr; Azure Active Directory &rarr; App registrations &rarr; <strong className="text-white/60">New registration</strong><br/>Name: "M-Challenge Scanner" &rarr; Supported accounts: "Single tenant" &rarr; Register</p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">2</div>
                    <div><div className="text-xs font-semibold text-white">Add Mail.Send Permission</div>
                    <p className="text-[11px] text-white/40 mt-0.5">In the app &rarr; <strong className="text-white/60">API permissions</strong> &rarr; Add permission &rarr; Microsoft Graph &rarr; <strong className="text-white/60">Application permissions</strong> &rarr; Search "Mail.Send" &rarr; Add &rarr; <strong className="text-amber-400">Grant admin consent</strong></p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">3</div>
                    <div><div className="text-xs font-semibold text-white">Create Client Secret</div>
                    <p className="text-[11px] text-white/40 mt-0.5">In the app &rarr; <strong className="text-white/60">Certificates &amp; secrets</strong> &rarr; New client secret &rarr; Copy the <strong className="text-emerald-400">Value</strong> (not the ID!)<br/>Then from the <strong className="text-white/60">Overview</strong> page, copy: <strong className="text-emerald-400">Application (client) ID</strong> and <strong className="text-emerald-400">Directory (tenant) ID</strong></p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/15 flex items-center justify-center text-[11px] font-bold text-blue-400 shrink-0">4</div>
                    <div><div className="text-xs font-semibold text-white">Paste Credentials Above</div>
                    <p className="text-[11px] text-white/40 mt-0.5">Fill in <strong className="text-white/60">Tenant ID</strong>, <strong className="text-white/60">Client ID</strong>, and <strong className="text-white/60">Client Secret</strong>. Set <strong className="text-white/60">From Email</strong> to a licensed mailbox in your tenant (e.g. info@yourcompany.com)</p></div>
                  </div>
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-emerald-500/15 flex items-center justify-center text-[11px] font-bold text-emerald-400 shrink-0">5</div>
                    <div><div className="text-xs font-semibold text-white">Verify, Save &amp; Test</div>
                    <p className="text-[11px] text-white/40 mt-0.5">Click <strong className="text-blue-400">{t("Verify")}</strong> to authenticate with Microsoft Graph &rarr; <strong className="text-blue-400">{t("Save Settings")}</strong> &rarr; <strong className="text-blue-400">{t("Send Test")}</strong>. If errors occur, check that admin consent was granted and the mailbox is licensed.</p></div>
                  </div>
                </div>
              )}
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

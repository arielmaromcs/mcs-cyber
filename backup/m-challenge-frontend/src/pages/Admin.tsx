import { useState, useEffect } from 'react';
import { Settings, Plus, Mail, CheckCircle2, User } from 'lucide-react';
import { api } from '../lib/api';
import { PageHeader, Card, Tabs, Badge, Input, Button } from '../components/ui';

export default function AdminPage() {
  const [tab, setTab] = useState('users');
  const [users, setUsers] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [smtpHost, setSmtpHost] = useState('');
  const [smtpPort, setSmtpPort] = useState('587');
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpPass, setSmtpPass] = useState('');
  const [msg, setMsg] = useState('');

  useEffect(() => {
    api.getUsers().then(setUsers).catch(() => {});
    api.adminStats().then(setStats).catch(() => {});
  }, []);

  const invite = async () => {
    if (!inviteEmail.trim()) return;
    try {
      await api.inviteUser(inviteEmail.trim(), 'BASIC_SCANS', 20);
      setMsg('User invited!'); setInviteEmail('');
      api.getUsers().then(setUsers);
    } catch (e: any) { setMsg(e.message); }
  };

  const saveEmail = async () => {
    try {
      await api.emailSettings('save', 'smtp', { smtp_host: smtpHost, smtp_port: parseInt(smtpPort), smtp_user: smtpUser, smtp_password: smtpPass });
      setMsg('Saved!');
    } catch (e: any) { setMsg(e.message); }
  };

  return (
    <div className="flex flex-col gap-4 animate-fade-in">
      <PageHeader icon={<Settings size={18} className="text-mc-brand" />} title="Admin Panel" subtitle="User management & configuration" />
      <Tabs tabs={[{ id: 'users', label: 'Users' }, { id: 'email', label: 'Email Settings' }]} active={tab} onChange={setTab} />

      {tab === 'users' && (
        <>
          {stats && (
            <div className="grid grid-cols-3 gap-3">
              {[['Total', stats.totalUsers], ['Admins', stats.admins], ['Regular', stats.regularUsers]].map(([l, v]) => (
                <Card key={l as string} className="text-center"><div className="text-[10px] text-mc-txt3 uppercase">{l}</div><div className="font-mono font-bold text-2xl text-white">{v}</div></Card>
              ))}
            </div>
          )}
          <Card>
            <div className="flex gap-2 mb-3">
              <Input value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="Email to invite..." className="flex-1" />
              <Button onClick={invite}><Plus size={13} />Invite</Button>
            </div>
            {msg && <p className="text-xs text-emerald-400 mb-2">{msg}</p>}
            {users.map((u: any) => (
              <div key={u.id} className="flex justify-between items-center px-3 py-2 bg-mc-bg1 rounded-md mb-1">
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-full bg-mc-bg3 flex items-center justify-center text-[10px] font-bold text-mc-txt3">
                    {(u.fullName || u.email)[0].toUpperCase()}
                  </div>
                  <div>
                    <div className="text-[11px] text-white">{u.fullName || u.email}</div>
                    <div className="text-[10px] text-mc-txt3">{u.email}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge severity={u.role === 'ADMIN' ? 'high' : u.role === 'FULL_SCANS' ? 'low' : 'info'}>{u.role}</Badge>
                  <span className="font-mono text-[10px] text-mc-txt3">{u.scansRemaining}</span>
                </div>
              </div>
            ))}
          </Card>
        </>
      )}

      {tab === 'email' && (
        <Card>
          <div className="text-xs font-semibold text-mc-txt2 mb-3">SMTP Configuration</div>
          <div className="space-y-2.5">
            <div><label className="text-[10px] text-mc-txt3 block mb-0.5">Host</label><Input value={smtpHost} onChange={e => setSmtpHost(e.target.value)} placeholder="smtp.example.com" /></div>
            <div><label className="text-[10px] text-mc-txt3 block mb-0.5">Port</label><Input value={smtpPort} onChange={e => setSmtpPort(e.target.value)} placeholder="587" /></div>
            <div><label className="text-[10px] text-mc-txt3 block mb-0.5">Username</label><Input value={smtpUser} onChange={e => setSmtpUser(e.target.value)} placeholder="user@example.com" /></div>
            <div><label className="text-[10px] text-mc-txt3 block mb-0.5">Password</label><Input type="password" value={smtpPass} onChange={e => setSmtpPass(e.target.value)} placeholder="••••••••" /></div>
          </div>
          {msg && <p className="text-xs text-emerald-400 mt-2">{msg}</p>}
          <div className="flex gap-2 mt-4">
            <Button variant="secondary"><Mail size={13} />Test</Button>
            <Button onClick={saveEmail}><CheckCircle2 size={13} />Save</Button>
          </div>
        </Card>
      )}
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Calendar, Plus, Play, Pause, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import { PageHeader, Card, Tabs, Badge, Button, scoreColor } from '../components/ui';

export default function SchedulesPage() {
  const [tab, setTab] = useState('list');
  const [schedules, setSchedules] = useState<any>({ web: [], email: [], threat: [] });
  const [logs, setLogs] = useState<any[]>([]);

  useEffect(() => {
    api.listSchedules().then(setSchedules).catch(() => {});
    api.scheduleLogs().then(setLogs).catch(() => {});
  }, []);

  const allScheds = [...(schedules.web || []).map((s: any) => ({ ...s, type: 'web' })),
    ...(schedules.email || []).map((s: any) => ({ ...s, type: 'email' })),
    ...(schedules.threat || []).map((s: any) => ({ ...s, type: 'threat' }))];

  const toggle = async (type: string, id: string, active: boolean) => {
    await api.toggleSchedule(type, id, active);
    api.listSchedules().then(setSchedules).catch(() => {});
  };

  const del = async (type: string, id: string) => {
    await api.deleteSchedule(type, id);
    api.listSchedules().then(setSchedules).catch(() => {});
  };

  return (
    <div className="flex flex-col gap-4 animate-fade-in">
      <PageHeader icon={<Calendar size={18} className="text-mc-brand" />} title="Scheduled Scans" subtitle="Automated recurring scans"
        action={<Button><Plus size={14} />New Schedule</Button>} />
      <Tabs tabs={[{ id: 'list', label: 'Schedules', count: allScheds.length }, { id: 'logs', label: 'Logs', count: logs.length }]} active={tab} onChange={setTab} />

      {tab === 'list' && (
        <div className="flex flex-col gap-1.5">
          {allScheds.length === 0 ? (
            <Card className="text-center py-10"><Calendar size={28} className="text-mc-txt3 mx-auto" /><div className="text-sm text-mc-txt3 mt-3">No schedules yet</div></Card>
          ) : allScheds.map((s: any) => (
            <Card key={s.id} className="flex justify-between items-center">
              <div className="flex items-center gap-2.5">
                <span className={`w-1.5 h-1.5 rounded-full ${s.isActive ? 'bg-emerald-400' : 'bg-mc-txt3'}`} />
                <div>
                  <div className="font-mono text-xs text-white">{s.url || s.domain || s.target}</div>
                  <div className="text-[10px] text-mc-txt3">{s.type} · {s.frequency?.toLowerCase()} · {s.isActive ? 'Active' : 'Paused'}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => toggle(s.type, s.id, s.isActive)} className="text-mc-txt3 hover:text-mc-brand transition-colors">
                  {s.isActive ? <Pause size={13} /> : <Play size={13} />}
                </button>
                <button onClick={() => del(s.type, s.id)} className="text-mc-txt3 hover:text-rose-400 transition-colors">
                  <Trash2 size={13} />
                </button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {tab === 'logs' && (
        <div className="flex flex-col gap-1.5">
          {logs.length === 0 ? (
            <Card className="text-center py-10"><div className="text-sm text-mc-txt3">No execution logs yet</div></Card>
          ) : logs.map((l: any, i: number) => (
            <Card key={i} className="flex justify-between items-center">
              <div className="flex items-center gap-2.5">
                <span className={`w-1.5 h-1.5 rounded-full ${l.status === 'success' ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                <div>
                  <div className="font-mono text-xs text-white">{l.target}</div>
                  <div className="text-[10px] text-mc-txt3">{l.scheduleType} · {new Date(l.executedAt).toLocaleString()}</div>
                </div>
              </div>
              <Badge severity={l.status === 'success' ? 'low' : 'high'}>{l.status}</Badge>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

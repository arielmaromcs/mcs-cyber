import { useState, useEffect } from 'react';
import { Globe } from 'lucide-react';
import { api } from '../lib/api';

export default function ClientIpBadge() {
  const [ip, setIp] = useState('');
  useEffect(() => { api.getClientIp().then(d => setIp(d.client_ip || '')).catch(() => {}); }, []);
  if (!ip || ip === 'Unknown') return null;
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-[11px] text-white/40">
      <Globe size={11} className="text-blue-400/60" />
      <span className="font-mono">Your IP: {ip}</span>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Globe, Mail, Clock, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from './ui';

interface ScanHistoryProps {
  type: 'web' | 'email';
  onSelectScan?: (scanId: string) => void;
}

export default function ScanHistory({ type, onSelectScan }: ScanHistoryProps) {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = type === 'web' ? await api.webScanHistory() : await api.emailScanHistory();
        setScans(data.scans || []);
      } catch { }
      setLoading(false);
    };
    fetch();
  }, [type]);

  const statusIcon = (status: string) => {
    if (status === 'COMPLETED') return <CheckCircle2 size={12} className="text-emerald-400" />;
    if (status === 'FAILED') return <AlertTriangle size={12} className="text-rose-400" />;
    return <Loader2 size={12} className="text-blue-400 animate-spin" />;
  };

  const scoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 50) return 'text-amber-400';
    return 'text-rose-400';
  };

  if (loading) return null;
  if (scans.length === 0) return null;

  return (
    <Card className="p-4 mt-4">
      <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
        <Clock size={14} className="text-white/30" />
        Scan History
      </h3>
      <div className="space-y-1">
        {scans.map((scan: any) => (
          <div
            key={scan.id}
            onClick={() => {
              if (onSelectScan) onSelectScan(scan.id);
              else window.location.href = `/${type === 'web' ? '' : 'email'}?scan=${scan.id}`;
            }}
            className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-blue-500/10 cursor-pointer group transition"
          >
            {type === 'web' ? (
              <Globe size={13} className="text-white/20 group-hover:text-blue-400" />
            ) : (
              <Mail size={13} className="text-white/20 group-hover:text-blue-400" />
            )}
            <span className="text-xs font-mono text-white group-hover:text-blue-300 min-w-[120px]">
              {scan.domain}
            </span>
            <span className="flex items-center gap-1">
              {statusIcon(scan.status)}
              <span className="text-[10px] text-white/30">{scan.status}</span>
            </span>
            {type === 'web' && scan.riskScore != null && (
              <span className={`text-xs font-semibold ${scoreColor(100 - scan.riskScore)}`}>
                {Math.round(100 - scan.riskScore)}%
              </span>
            )}
            {type === 'email' && scan.emailSecurityScore != null && (
              <span className={`text-xs font-semibold ${scoreColor(scan.emailSecurityScore)}`}>
                {Math.round(scan.emailSecurityScore)}%
              </span>
            )}
            <span className="text-[10px] text-white/15 ml-auto">
              {new Date(scan.createdAt).toLocaleDateString()}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

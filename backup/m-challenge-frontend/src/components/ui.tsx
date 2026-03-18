import { ReactNode } from 'react';
import { Loader2, CheckCircle2 } from 'lucide-react';

// ── Severity colors ──
const SEV: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: 'bg-rose-500/10 border-rose-500/25', text: 'text-rose-400', dot: 'bg-rose-500' },
  high: { bg: 'bg-orange-500/10 border-orange-500/25', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium: { bg: 'bg-amber-400/10 border-amber-400/25', text: 'text-amber-400', dot: 'bg-amber-400' },
  low: { bg: 'bg-blue-400/10 border-blue-400/25', text: 'text-blue-400', dot: 'bg-blue-400' },
  info: { bg: 'bg-slate-400/10 border-slate-400/20', text: 'text-slate-400', dot: 'bg-slate-400' },
};

export function scoreColor(v: number) {
  return v >= 80 ? 'text-emerald-400' : v >= 50 ? 'text-blue-400' : v >= 20 ? 'text-amber-400' : 'text-rose-400';
}

export function scoreLabel(v: number) {
  return v >= 80 ? 'Low Risk' : v >= 50 ? 'Medium' : v >= 20 ? 'High Risk' : 'Critical';
}

// ── Badge ──
export function Badge({ severity, children }: { severity: string; children?: ReactNode }) {
  const s = SEV[severity] || SEV.info;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${s.bg} ${s.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {children || severity}
    </span>
  );
}

// ── Progress Circle ──
export function ProgressCircle({ progress, status = 'running', size = 90 }: { progress: number; status?: string; size?: number }) {
  const r = (size - 8) / 2;
  const c = 2 * Math.PI * r;
  const off = c - (progress / 100) * c;
  const col = status === 'done' ? '#34d399' : '#3b8bff';

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#203060" strokeWidth={4} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={col} strokeWidth={4} fill="none"
          strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" className="transition-all duration-500" />
      </svg>
      <div className="absolute text-center">
        {status === 'running' && <Loader2 size={14} className="animate-spin-slow text-mc-brand mx-auto" />}
        {status === 'done' && <CheckCircle2 size={14} className="text-mc-emerald mx-auto" />}
        <div className="font-mono font-bold text-white text-base mt-0.5">{Math.round(progress)}%</div>
      </div>
    </div>
  );
}

// ── Score Display ──
export function ScoreDisplay({ value, label, size = 'md' }: { value: number; label?: string; size?: string }) {
  const fs = size === 'lg' ? 'text-5xl' : size === 'sm' ? 'text-2xl' : 'text-4xl';
  return (
    <div className="text-center">
      <div className={`font-mono font-bold ${fs} ${scoreColor(value)}`}>{value}</div>
      <div className={`text-[10px] font-semibold mt-1 px-3 py-0.5 rounded-full inline-block ${scoreColor(value)} bg-current/10`}>
        {label || scoreLabel(value)}
      </div>
    </div>
  );
}

// ── Card ──
export function Card({ children, className = '', style }: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  return <div className={`bg-mc-bg2 border border-mc-bg3 rounded-xl p-4 ${className}`} style={style}>{children}</div>;
}

export function CardGlow({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`bg-mc-bg2 border border-mc-brand/20 rounded-xl p-5 shadow-[0_0_0_1px_rgba(59,139,255,0.2),0_8px_32px_rgba(0,0,0,0.4)] ${className}`}>{children}</div>;
}

// ── Tabs ──
export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: string; count?: number }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div className="flex gap-0.5 p-1 bg-mc-bg1 rounded-lg border border-mc-bg3">
      {tabs.map(t => (
        <button key={t.id} onClick={() => onChange(t.id)}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-[11px] font-medium transition-all
            ${active === t.id ? 'bg-mc-brand/10 text-mc-brand border border-mc-brand/20' : 'text-mc-txt3 border border-transparent hover:text-mc-txt2'}`}>
          {t.label}
          {t.count != null && <span className="text-[9px] px-1.5 py-px rounded-md bg-mc-bg3 text-mc-txt3">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ── Page Header ──
export function PageHeader({ icon, title, subtitle, action }: { icon: ReactNode; title: string; subtitle: string; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-mc-brand/10 border border-mc-brand/20 flex items-center justify-center">{icon}</div>
        <div>
          <h1 className="font-mono font-bold text-lg text-white">{title}</h1>
          <p className="text-xs text-mc-txt3">{subtitle}</p>
        </div>
      </div>
      {action}
    </div>
  );
}

// ── Tag ──
export function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-block px-2 py-0.5 rounded text-[9px] font-semibold bg-mc-bg3 text-mc-txt3 uppercase tracking-wider">{children}</span>;
}

// ── Input ──
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`w-full px-3.5 py-2.5 bg-mc-bg1 border border-mc-bg4 rounded-lg text-mc-txt text-[13px] font-mono
    focus:border-mc-brand focus:ring-2 focus:ring-mc-brand/20 outline-none transition-all ${props.className || ''}`} />;
}

// ── Button ──
export function Button({ children, variant = 'primary', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' }) {
  const base = 'inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-[13px] font-semibold cursor-pointer transition-all disabled:opacity-40 disabled:cursor-not-allowed';
  const v = variant === 'primary' ? 'bg-mc-brand text-white hover:bg-mc-brand/90' : 'bg-mc-bg3 text-mc-txt2 border border-mc-bg4 hover:bg-mc-bg4';
  return <button {...props} className={`${base} ${v}`}>{children}</button>;
}
 

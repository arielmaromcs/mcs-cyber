import { ReactNode, CSSProperties } from 'react';

/* ─── Severity helpers ─── */
const SEV_COLORS: Record<string, { text: string; bg: string; dot: string }> = {
  critical: { text: 'text-mc-rose', bg: 'sev-bg-critical', dot: 'bg-mc-rose' },
  high: { text: 'text-mc-orange', bg: 'sev-bg-high', dot: 'bg-mc-orange' },
  medium: { text: 'text-mc-amber', bg: 'sev-bg-medium', dot: 'bg-mc-amber' },
  low: { text: 'text-mc-brand', bg: 'sev-bg-low', dot: 'bg-mc-brand' },
  info: { text: 'text-mc-txt3', bg: 'sev-bg-info', dot: 'bg-mc-txt3' },
};

export function scoreColor(s: number) { return s >= 80 ? '#34d399' : s >= 60 ? '#2d7aff' : s >= 40 ? '#fbbf24' : '#fb7185'; }
export function scoreLabel(s: number) { return s >= 80 ? 'Low Risk' : s >= 60 ? 'Medium' : s >= 40 ? 'High' : 'Critical'; }
export function sevColor(sev: string) { return SEV_COLORS[sev?.toLowerCase()] || SEV_COLORS.info; }

/* ─── Badge ─── */
export function Badge({ severity, children, className = '' }: { severity: string; children?: ReactNode; className?: string }) {
  const c = sevColor(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold border ${c.bg} ${c.text} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {children || severity}
    </span>
  );
}

/* ─── Card ─── */
export function Card({ children, className = '', glow = false, style }: { children: ReactNode; className?: string; glow?: boolean; style?: CSSProperties }) {
  return (
    <div className={`bg-mc-card border border-mc-cardBorder rounded-xl ${glow ? 'card-glow' : ''} ${className}`} style={style}>
      {children}
    </div>
  );
}

/* ─── Score Display ─── */
export function ScoreDisplay({ score, label, size = 'md' }: { score: number; label?: string; size?: 'sm' | 'md' | 'lg' }) {
  const color = scoreColor(score);
  const sz = size === 'lg' ? 'text-5xl' : size === 'md' ? 'text-3xl' : 'text-xl';
  return (
    <div className="text-center">
      <div className={`${sz} font-bold font-mono`} style={{ color }}>{Math.round(score)}</div>
      <div className="text-[11px] text-mc-txt3 mt-0.5">{label || scoreLabel(score)}</div>
    </div>
  );
}

/* ─── Progress Circle (SVG) ─── */
export function ProgressCircle({ value, size = 64, stroke = 4, color }: { value: number; size?: number; stroke?: number; color?: string }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (Math.min(100, Math.max(0, value)) / 100) * circ;
  const fill = color || scoreColor(value);

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={fill} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" className="score-ring" />
      </svg>
      <span className="absolute text-sm font-bold font-mono" style={{ color: fill }}>{Math.round(value)}</span>
    </div>
  );
}

/* ─── Tabs ─── */
export function Tabs({ tabs, active, onChange }: { tabs: { key: string; label: string; count?: number }[]; active: string; onChange: (k: string) => void }) {
  return (
    <div className="flex gap-0.5 border-b border-mc-cardBorder mb-4 overflow-x-auto hide-scrollbar">
      {tabs.map(t => (
        <button key={t.key} onClick={() => onChange(t.key)}
          className={`px-4 py-2.5 text-[13px] font-medium whitespace-nowrap transition-all border-b-2
            ${active === t.key ? 'border-mc-brand text-mc-brand' : 'border-transparent text-mc-txt3 hover:text-mc-txt2'}`}>
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 px-1.5 py-0.5 text-[9px] rounded-full bg-mc-bg2 text-white">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ─── Button ─── */
export function Button({ children, variant = 'primary', size = 'md', disabled, className = '', ...props }:
  { children: ReactNode; variant?: 'primary' | 'secondary' | 'danger' | 'ghost'; size?: 'sm' | 'md' | 'lg'; disabled?: boolean; className?: string } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const base = 'inline-flex items-center justify-center gap-2 font-medium rounded-lg transition-all disabled:opacity-40 disabled:pointer-events-none';
  const sizes = { sm: 'px-3 py-1.5 text-xs', md: 'px-4 py-2 text-sm', lg: 'px-6 py-2.5 text-sm' };
  const variants = {
    primary: 'bg-mc-brand text-white hover:bg-mc-brandLight shadow-lg shadow-mc-brand/20',
    secondary: 'bg-mc-bg2 text-mc-txt2 border border-mc-cardBorder hover:bg-mc-bg3 hover:text-white',
    danger: 'bg-mc-rose/10 text-mc-rose border border-mc-rose/20 hover:bg-mc-rose/20',
    ghost: 'text-mc-txt3 hover:text-mc-txt2 hover:bg-mc-bg2',
  };
  return <button className={`${base} ${sizes[size]} ${variants[variant]} ${className}`} disabled={disabled} {...props}>{children}</button>;
}

/* ─── Input ─── */
export function Input({ label, style, className, ...props }: { label?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div>
      {label && <label className="block text-xs text-mc-txt3 mb-1 font-medium">{label}</label>}
      <input {...props} className={`w-full px-3 py-2 bg-mc-bg2 border border-mc-cardBorder rounded-lg text-sm text-mc-txt placeholder:text-mc-txt3/50 focus:border-mc-brand/50 focus:ring-1 focus:ring-mc-brand/20 outline-none transition ${className || ''}`} style={style} />
    </div>
  );
}

/* ─── Tag ─── */
export function Tag({ children, color = 'blue' }: { children: ReactNode; color?: 'blue' | 'green' | 'amber' | 'red' | 'gray' }) {
  const colors = { blue: 'bg-mc-brand/10 text-mc-brand', green: 'bg-mc-emerald/10 text-mc-emerald', amber: 'bg-mc-amber/10 text-mc-amber', red: 'bg-mc-rose/10 text-mc-rose', gray: 'bg-mc-bg2 text-mc-txt3' };
  return <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${colors[color]}`}>{children}</span>;
}

/* ─── Page Header (used inside hero sections) ─── */
export function PageHeader({ icon: Icon, title, subtitle, action }: { icon?: any; title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="flex items-start justify-between">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
            <Icon size={20} className="text-white" />
          </div>
        )}
        <div>
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          {subtitle && <p className="text-sm text-blue-100/70 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

/* ─── Empty State ─── */
export function EmptyState({ icon: Icon, title, subtitle }: { icon?: any; title: string; subtitle?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      {Icon && <Icon size={32} className="text-mc-txt3/30 mb-3" />}
      <div className="text-sm text-mc-txt3 font-medium">{title}</div>
      {subtitle && <div className="text-xs text-mc-txt3/60 mt-1">{subtitle}</div>}
    </div>
  );
}

/* ─── Loading Spinner ─── */
export function Spinner({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={`animate-spin ${className}`}>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" fill="none" strokeDasharray="31.4 31.4" strokeLinecap="round" />
    </svg>
  );
}

import { useLang } from '../hooks/useLang';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Eye, Zap, Target, Globe, Mail, Crosshair } from 'lucide-react';
import { Card } from '../components/ui';

const FEATURES = [
  { icon: Globe, titleKey: 'Web Security Scanner', descKey: 'Web Security Scanner desc', to: '/web' },
  { icon: Mail, titleKey: 'Email Security Scanner', descKey: 'Email Security Scanner desc', to: '/email' },
  { icon: Crosshair, titleKey: 'Threat Intelligence', descKey: 'Threat Intelligence desc', to: '/threat' },
  { icon: Target, titleKey: 'MITRE ATT&CK Analysis', descKey: 'MITRE ATT&CK Analysis desc', to: '/mitre' },
  { icon: Lock, titleKey: 'Defensive Only', descKey: 'Defensive Only desc' },
  { icon: Eye, titleKey: 'Exposure Discovery', descKey: 'Exposure Discovery desc' },
];

export default function About() {
  const { t } = useLang();
  const navigate = useNavigate();
  return (
    <div>
      {/* Hero - matches screenshot exactly */}
      <div className="hero-bg py-20 px-4 text-center relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(45,122,255,0.08)_0%,transparent_70%)]" />
        <div className="relative z-10 max-w-[700px] mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-white/8 border border-white/10 rounded-full text-sm text-blue-100/80 mb-8">
            <Shield size={14} /> {t("about_badge")}
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-6 leading-tight">{t("about_title")}</h1>
          <p className="text-base text-blue-100/60 leading-relaxed max-w-[550px] mx-auto">
{t("about_subtitle")}
          </p>
        </div>
      </div>

      {/* Features Grid */}
      <div className="max-w-[1000px] mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f, i) => (
            <div key={i} onClick={() => (f as any).to && navigate((f as any).to)} className={(f as any).to ? "cursor-pointer" : ""}><Card glow className="p-5 hover:border-mc-brand/30 transition-colors group" style={{ animationDelay: `${i * 80}ms` }}>
              <div className="w-10 h-10 rounded-xl bg-mc-brand/10 flex items-center justify-center mb-3 group-hover:bg-mc-brand/20 transition">
                <f.icon size={20} className="text-mc-brand" />
              </div>
              <h3 className="text-sm font-semibold text-white mb-1.5">{t(f.titleKey)}</h3>
              <p className="text-xs text-mc-txt3 leading-relaxed">{t(f.descKey)}</p>
            </Card></div>
          ))}
        </div>

        {/* Tech Stack */}
        <Card className="p-6 mt-8">
          <h2 className="text-lg font-bold text-white mb-4">{t("Technology Stack")}</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: t('Backend'), items: ['Fastify', 'Prisma', 'BullMQ', 'TypeScript'] },
              { label: t('Frontend'), items: ['React', 'Tailwind CSS', 'Vite', 'Lucide Icons'] },
              { label: t('Integrations'), items: ['Google DNS', 'crt.sh', 'NMAP API', 'AbuseIPDB'] },
              { label: t('Security'), items: ['JWT Auth', 'RBAC', 'OWASP Rules', 'MITRE ATT&CK'] },
            ].map(g => (
              <div key={g.label}>
                <div className="text-[10px] text-mc-brand font-semibold uppercase tracking-wider mb-2">{g.label}</div>
                {g.items.map(item => <div key={item} className="text-xs text-mc-txt2 py-0.5">{item}</div>)}
              </div>
            ))}
          </div>
        </Card>

        {/* Scoring */}
        <Card className="p-6 mt-4">
          <h2 className="text-lg font-bold text-white mb-4">{t("Scoring Methodology")}</h2>
          <div className="space-y-3">
            <div className="bg-mc-bg2 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-white mb-2">Web Security Score (0-100)</h3>
              <div className="text-xs text-mc-txt3 space-y-1">
                <div>{t("web_score_critical")}</div>
                <div>{t("web_score_high")}</div>
                <div>{t("web_score_medium")}</div>
                <div>{t("web_score_low")}</div>
                <div>{t("web_score_exposure")}</div>
                <div>{t("web_score_caps")}</div>
              </div>
            </div>
            <div className="bg-mc-bg2 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-white mb-2">Email Security Score (0-100)</h3>
              <div className="text-xs text-mc-txt3 space-y-1">
                <div>{t("email_score_breakdown")}</div>
                <div>{t("email_score_infra")}</div>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

import { useState } from 'react';
import { Globe, Mail, Crosshair, Target, Calendar, Settings, HelpCircle, ChevronDown, ChevronUp, CheckCircle2, ArrowRight } from 'lucide-react';
import { useLang } from '../hooks/useLang';

export default function HelpCenter() {
  const { t, lang } = useLang();
  const [open, setOpen] = useState<string | null>(null);

  const sections = [
    {
      id: 'web', icon: Globe, color: 'blue',
      title: 'Web Scanner',
      what: t('help_web_what'),
      steps: [t('help_web_s1'), t('help_web_s2'), t('help_web_s3'), t('help_web_s4'), t('help_web_s5')],
      results: [
        { label: t('help_web_r1l'), desc: t('help_web_r1d') },
        { label: t('help_web_r2l'), desc: t('help_web_r2d') },
        { label: t('help_web_r3l'), desc: t('help_web_r3d') },
      ],
      next: [t('help_web_n1'), t('help_web_n2'), t('help_web_n3')],
    },
    {
      id: 'email', icon: Mail, color: 'amber',
      title: 'Email Scanner',
      what: t('help_email_what'),
      steps: [t('help_email_s1'), t('help_email_s2'), t('help_email_s3'), t('help_email_s4')],
      results: [
        { label: t('help_email_r1l'), desc: t('help_email_r1d') },
        { label: t('help_email_r2l'), desc: t('help_email_r2d') },
        { label: t('help_email_r3l'), desc: t('help_email_r3d') },
      ],
      next: [t('help_email_n1'), t('help_email_n2'), t('help_email_n3')],
    },
    {
      id: 'threat', icon: Crosshair, color: 'rose',
      title: 'Threat Intelligence',
      what: t('help_threat_what'),
      steps: [t('help_threat_s1'), t('help_threat_s2'), t('help_threat_s3'), t('help_threat_s4'), t('help_threat_s5')],
      results: [
        { label: t('help_threat_r1l'), desc: t('help_threat_r1d') },
        { label: t('help_threat_r2l'), desc: t('help_threat_r2d') },
        { label: t('help_threat_r3l'), desc: t('help_threat_r3d') },
      ],
      next: [t('help_threat_n1'), t('help_threat_n2'), t('help_threat_n3')],
    },
    {
      id: 'mitre', icon: Target, color: 'purple',
      title: 'MITRE ATT&CK Analysis',
      what: t('help_mitre_what'),
      steps: [t('help_mitre_s1'), t('help_mitre_s2'), t('help_mitre_s3'), t('help_mitre_s4'), t('help_mitre_s5')],
      results: [
        { label: t('help_mitre_r1l'), desc: t('help_mitre_r1d') },
        { label: t('help_mitre_r2l'), desc: t('help_mitre_r2d') },
        { label: t('help_mitre_r3l'), desc: t('help_mitre_r3d') },
      ],
      next: [t('help_mitre_n1'), t('help_mitre_n2'), t('help_mitre_n3')],
    },
    {
      id: 'schedules', icon: Calendar, color: 'emerald',
      title: t('Scheduled Scans title'),
      what: t('help_sched_what'),
      steps: [t('help_sched_s1'), t('help_sched_s2'), t('help_sched_s3'), t('help_sched_s4'), t('help_sched_s5'), t('help_sched_s6'), t('help_sched_s7')],
      results: [
        { label: t('help_sched_r1l'), desc: t('help_sched_r1d') },
        { label: t('help_sched_r2l'), desc: t('help_sched_r2d') },
        { label: t('help_sched_r3l'), desc: t('help_sched_r3d') },
      ],
      next: [t('help_sched_n1'), t('help_sched_n2'), t('help_sched_n3')],
    },
    {
      id: 'admin', icon: Settings, color: 'slate',
      title: 'Admin Panel',
      what: t('help_admin_what'),
      steps: [t('help_admin_s1'), t('help_admin_s2'), t('help_admin_s3'), t('help_admin_s4'), t('help_admin_s5')],
      results: [
        { label: t('help_admin_r1l'), desc: t('help_admin_r1d') },
        { label: t('help_admin_r2l'), desc: t('help_admin_r2d') },
        { label: t('help_admin_r3l'), desc: t('help_admin_r3d') },
      ],
      next: [t('help_admin_n1'), t('help_admin_n2'), t('help_admin_n3')],
    },
  ];

  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    rose: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    slate: 'text-slate-300 bg-slate-500/10 border-slate-500/20',
  };

  return (
    <div dir={lang === 'he' ? 'rtl' : 'ltr'}>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
            <HelpCircle size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">{t('Help Center')}</h1>
            <p className="text-sm text-blue-100/60">{t('help_subtitle')}</p>
          </div>
        </div>
      </div>

      <div className="max-w-[900px] mx-auto px-4 py-6 space-y-3">
        {sections.map(s => {
          const isOpen = open === s.id;
          const colors = colorMap[s.color];
          return (
            <div key={s.id} className="bg-mc-card border border-mc-cardBorder rounded-2xl overflow-hidden">
              <button
                onClick={() => setOpen(isOpen ? null : s.id)}
                className="w-full flex items-center gap-4 px-5 py-4 hover:bg-white/[0.02] transition"
              >
                <div className={`w-9 h-9 rounded-xl border flex items-center justify-center shrink-0 ${colors}`}>
                  <s.icon size={17} />
                </div>
                <span className="text-sm font-semibold text-white flex-1 text-left">{s.title}</span>
                {isOpen ? <ChevronUp size={16} className="text-mc-txt3" /> : <ChevronDown size={16} className="text-mc-txt3" />}
              </button>

              {isOpen && (
                <div className="px-5 pb-5 space-y-5 border-t border-mc-cardBorder">
                  <div className="pt-4">
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">{t('help_what')}</div>
                    <p className="text-sm text-mc-txt2 leading-relaxed">{s.what}</p>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">{t('help_how')}</div>
                    <ol className="space-y-1.5">
                      {s.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm text-mc-txt2">
                          <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5 ${colors}`}>{i + 1}</span>
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">{t('help_results')}</div>
                    <div className="space-y-2">
                      {s.results.map((r, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <CheckCircle2 size={14} className={`shrink-0 mt-0.5 ${colors.split(' ')[0]}`} />
                          <div className="text-sm text-mc-txt2"><span className="text-white font-medium">{r.label}:</span> {r.desc}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">{t('help_next')}</div>
                    <div className="space-y-1.5">
                      {s.next.map((n, i) => (
                        <div key={i} className="flex items-start gap-2 text-sm text-mc-txt2">
                          <ArrowRight size={14} className={`shrink-0 mt-0.5 ${colors.split(' ')[0]}`} />
                          {n}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

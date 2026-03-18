import { useState } from 'react';
import { Shield, Eye, Lock, Zap, Globe, Mail, Crosshair, Target, ChevronRight } from 'lucide-react';
import { PageHeader, Card, CardGlow, Button } from '../components/ui';

export default function AboutPage() {
  const [lang, setLang] = useState<'en' | 'he'>('en');
  const en = lang === 'en';

  const caps = [
    { Icon: Mail, t: en ? 'Email Security' : 'אבטחת דוא"ל', d: en ? 'SPF, DKIM, DMARC · Blacklist · AbuseIPDB' : 'SPF, DKIM, DMARC · רשימות שחורות' },
    { Icon: Globe, t: en ? 'Web Exposure' : 'חשיפת ווב', d: en ? 'TLS/SSL · Headers · Cookies · 100+ rules' : 'TLS/SSL · כותרות · עוגיות · 100+ כללים' },
    { Icon: Crosshair, t: en ? 'Threat Intelligence' : 'מודיעין איומים', d: en ? 'NMAP · CVE correlation · NSE scripts' : 'NMAP · מיפוי CVE · סקריפטים' },
    { Icon: Target, t: en ? 'MITRE ATT&CK' : 'מיפוי MITRE', d: en ? 'Multi-vector · Attack paths · Remediation' : 'רב-וקטורי · נתיבי תקיפה · תיקון' },
  ];

  const diffs = en
    ? ['Detection only — no exploitation', 'MITRE ATT&CK framework mapping', 'Multi-vector scanning (Web + Email + Network)', 'Real-time progress tracking', 'Scheduled automated scanning', 'Executive-level reporting']
    : ['זיהוי בלבד — ללא ניצול', 'מיפוי MITRE ATT&CK', 'סריקה רב-וקטורית', 'מעקב בזמן אמת', 'אוטומציה מתוזמנת', 'דיווח ברמת מנהלים'];

  return (
    <div className="flex flex-col gap-5 animate-fade-in" style={{ direction: en ? 'ltr' : 'rtl' }}>
      <PageHeader icon={<Shield size={18} className="text-mc-brand" />}
        title={en ? 'About M-Challenge' : 'אודות M-Challenge'}
        subtitle={en ? 'Enterprise external attack surface analysis' : 'ניתוח משטח תקיפה חיצוני ארגוני'}
        action={<Button variant="secondary" onClick={() => setLang(en ? 'he' : 'en')}>{en ? 'עברית' : 'English'}</Button>} />

      <CardGlow>
        <div className="flex items-center gap-2 mb-2.5"><Eye size={15} className="text-mc-brand" /><span className="font-mono font-bold text-sm text-white">{en ? 'Our Vision' : 'החזון שלנו'}</span></div>
        <p className="text-xs text-mc-txt3 leading-relaxed">
          {en ? 'M-Challenge provides organizations with a comprehensive view of their external security posture from an attacker\'s perspective — without running actual attacks. We perform only passive and safe-active detection, mapping all findings to MITRE ATT&CK.'
            : 'M-Challenge מספקת לארגונים תמונה מקיפה של מצב האבטחה החיצוני מנקודת מבטו של תוקף — ללא הפעלת מתקפות. אנו מבצעים רק זיהוי פסיבי ובטוח, וממפים ממצאים ל-MITRE ATT&CK.'}
        </p>
      </CardGlow>

      <div className="grid grid-cols-2 gap-3">
        {caps.map((c, i) => (
          <Card key={i}>
            <div className="flex gap-3">
              <div className="w-9 h-9 rounded-lg bg-mc-brand/10 border border-mc-brand/20 flex items-center justify-center shrink-0">
                <c.Icon size={15} className="text-mc-brand" />
              </div>
              <div><div className="text-xs font-semibold text-white mb-1">{c.t}</div><div className="text-[10px] text-mc-txt3 leading-relaxed">{c.d}</div></div>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <div className="flex items-center gap-2 mb-3"><Zap size={14} className="text-cyan-400" /><span className="font-mono font-bold text-sm text-white">{en ? 'Key Differentiators' : 'מבדלים עיקריים'}</span></div>
        <div className="grid grid-cols-2 gap-1.5">
          {diffs.map((d, i) => (
            <div key={i} className="flex items-center gap-1.5 text-[11px]">
              <ChevronRight size={12} className="text-mc-brand shrink-0" /><span className="text-mc-txt2">{d}</span>
            </div>
          ))}
        </div>
      </Card>

      <CardGlow className="text-center py-6">
        <Lock size={22} className="text-mc-brand mx-auto" />
        <div className="font-mono font-bold text-sm text-white mt-2">{en ? 'Our Mission' : 'המשימה שלנו'}</div>
        <p className="text-xs text-mc-txt3 max-w-md mx-auto mt-2 leading-relaxed">
          {en ? 'Making professional-grade security assessment accessible to every organization, enabling proactive defense through continuous visibility into their external attack surface.'
            : 'להנגיש הערכת אבטחה מקצועית לכל ארגון, ולאפשר הגנה פרואקטיבית באמצעות ראות מתמדת במשטח התקיפה.'}
        </p>
      </CardGlow>
    </div>
  );
}

import { useState } from 'react';
import { Globe, Mail, Crosshair, Target, Calendar, Settings, HelpCircle, ChevronDown, ChevronUp, CheckCircle2, ArrowRight } from 'lucide-react';

const sections = [
  {
    id: 'web',
    icon: Globe,
    color: 'blue',
    title: 'Web Scanner',
    what: 'Analyzes websites for security vulnerabilities including SSL/TLS issues, exposed headers, XSS risks, outdated software, and misconfigurations.',
    steps: [
      'Go to Web Scanner from the sidebar',
      'Enter the full URL (e.g. https://yoursite.com)',
      'Select a scan profile: Quick, Standard, or Deep',
      'Click Scan and wait for results',
      'Review findings grouped by severity',
    ],
    results: [
      { label: 'Critical / High', desc: 'Immediate action required — these expose your site to attacks' },
      { label: 'Medium', desc: 'Should be addressed soon — potential attack vectors' },
      { label: 'Low / Info', desc: 'Best practices and informational notices' },
    ],
    next: ['Fix Critical and High findings first', 'Re-scan after making changes', 'Schedule recurring scans for continuous monitoring'],
  },
  {
    id: 'email',
    icon: Mail,
    color: 'amber',
    title: 'Email Scanner',
    what: 'Checks your domain\'s email security posture by analyzing SPF, DKIM, DMARC records, open mail ports, and blacklist status.',
    steps: [
      'Go to Email Scanner from the sidebar',
      'Enter your domain name (e.g. yourdomain.com)',
      'Click Scan — no login required',
      'Review DNS record status and recommendations',
    ],
    results: [
      { label: 'SPF Missing / Weak', desc: 'Attackers can send emails pretending to be you' },
      { label: 'DMARC Missing', desc: 'No policy to handle unauthenticated emails' },
      { label: 'Blacklisted IPs', desc: 'Your mail server may be flagged as spam' },
    ],
    next: ['Add or fix SPF, DKIM, DMARC records via your DNS provider', 'Set DMARC policy to "reject" for maximum protection', 'Monitor blacklist status regularly'],
  },
  {
    id: 'threat',
    icon: Crosshair,
    color: 'rose',
    title: 'Threat Intelligence',
    what: 'Performs port scanning and service discovery on a target IP or domain using Nmap, identifying exposed services and potential attack surfaces.',
    steps: [
      'Go to Threat Intelligence from the sidebar',
      'Enter an IP address or domain',
      'Choose a scan profile (Quick, Service Discovery, or Security Posture)',
      'Configure DNS record types to resolve (A, MX, TXT)',
      'Click Start Scan and monitor progress',
    ],
    results: [
      { label: 'Open Ports', desc: 'Services exposed to the internet — reduce attack surface by closing unused ports' },
      { label: 'Service Versions', desc: 'Outdated versions may have known CVEs' },
      { label: 'CVE Findings', desc: 'Known vulnerabilities matched against detected services' },
    ],
    next: ['Close unnecessary ports via firewall rules', 'Update services with known CVEs', 'Use scheduled scans to detect changes over time'],
  },
  {
    id: 'mitre',
    icon: Target,
    color: 'purple',
    title: 'MITRE ATT&CK Analysis',
    what: 'Maps your scan findings to the MITRE ATT&CK framework — a globally recognized knowledge base of attacker tactics and techniques.',
    steps: [
      'Run a Web or Threat Intelligence scan first',
      'Go to MITRE Analysis from the sidebar',
      'Select a recent scan to analyze',
      'Review mapped tactics and techniques',
      'Use the visual matrix to understand your exposure',
    ],
    results: [
      { label: 'Tactics', desc: 'High-level attacker goals (e.g. Initial Access, Persistence, Exfiltration)' },
      { label: 'Techniques', desc: 'Specific methods attackers use — each mapped to your findings' },
      { label: 'Coverage Score', desc: 'How many ATT&CK techniques your current posture addresses' },
    ],
    next: ['Focus on high-impact tactics first', 'Share the report with your security team', 'Use findings to prioritize remediation efforts'],
  },
  {
    id: 'schedules',
    icon: Calendar,
    color: 'emerald',
    title: 'Scheduled Scans',
    what: 'Automates recurring security scans on your assets so you\'re always aware of changes in your security posture without manual effort.',
    steps: [
      'Go to Scheduled Scans from the sidebar',
      'Click "+ New Schedule"',
      'Select scan type: Web, Email, or Port Exposure',
      'Enter the target URL, domain, or IP',
      'Add a description (e.g. "Production Server")',
      'Set frequency (Daily / Weekly / Monthly) and time',
      'Add notification emails',
      'Click Create',
    ],
    results: [
      { label: 'Active', desc: 'Schedule is running at the defined interval' },
      { label: 'Execution Logs', desc: 'History of all past scan runs with status and targets' },
      { label: 'Email Reports', desc: 'Automatic reports sent to your team after each scan' },
    ],
    next: ['Use the ⚡ button to run a schedule immediately', 'Add multiple email recipients for team visibility', 'Use descriptions to identify assets clearly in reports'],
  },
  {
    id: 'admin',
    icon: Settings,
    color: 'slate',
    title: 'Admin Panel',
    what: 'Manage users, roles, scan limits, and email delivery settings for the entire platform.',
    steps: [
      'Go to Admin Panel (visible to Admins only)',
      'Invite new users via email — they receive login credentials automatically',
      'Assign roles: Basic, Full, or Admin',
      'Edit users to change their name or reset their password',
      'Configure email settings (SMTP or Microsoft 365) for report delivery',
      'Verify and test email before saving',
    ],
    results: [
      { label: 'Basic', desc: 'Access to Web and Email scanners only' },
      { label: 'Full', desc: 'All scanners including Threat Intel and MITRE' },
      { label: 'Admin', desc: 'Full access + user management + system settings' },
    ],
    next: ['Always verify email settings before enabling scheduled scans', 'Reset passwords for users who are locked out', 'Monitor user activity via scan history'],
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

export default function HelpCenter() {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div>
      <div className="hero-bg py-10 px-4">
        <div className="max-w-[900px] mx-auto flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center">
            <HelpCircle size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Help Center</h1>
            <p className="text-sm text-blue-100/60">Learn how to use each module effectively</p>
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
                  {/* What it does */}
                  <div className="pt-4">
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">What it does</div>
                    <p className="text-sm text-mc-txt2 leading-relaxed">{s.what}</p>
                  </div>

                  {/* How to use */}
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">How to use</div>
                    <ol className="space-y-1.5">
                      {s.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm text-mc-txt2">
                          <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5 ${colors}`}>{i + 1}</span>
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>

                  {/* Results */}
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">What the results mean</div>
                    <div className="space-y-2">
                      {s.results.map((r, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <CheckCircle2 size={14} className={`shrink-0 mt-0.5 ${colors.split(' ')[0]}`} />
                          <div className="text-sm text-mc-txt2"><span className="text-white font-medium">{r.label}:</span> {r.desc}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Next actions */}
                  <div>
                    <div className="text-[10px] font-semibold text-mc-txt3 uppercase tracking-wider mb-2">Recommended next actions</div>
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

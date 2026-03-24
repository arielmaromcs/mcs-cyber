import ClientIpBadge from "./ClientIpBadge";
import { ReactNode, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { Shield, Globe, Mail, Crosshair, Target, Calendar, Settings, Info, LogOut, Languages, ChevronDown, PanelLeftClose, PanelLeft, HelpCircle, Lock, Users, Zap, ShieldAlert } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useLang } from '../hooks/useLang';

const NAV_ITEMS = [
  { to: '/about', icon: Info, label: 'About', requiresAuth: '' },
  { to: '/admin', icon: Settings, label: 'Admin Panel', requiresAuth: 'admin' },
  { to: '/web', icon: Globe, label: 'Web Scanner', requiresAuth: '' },
  { to: '/email', icon: Mail, label: 'Email Scanner', requiresAuth: '' },
  { to: '/threat', icon: Crosshair, label: 'Threat Intelligence', requiresAuth: 'full' },
  { to: '/mitre', icon: Target, label: 'MITRE Analysis', requiresAuth: 'full' },
  { to: '/schedules', icon: Calendar, label: 'Scheduled Scans', requiresAuth: 'any' },
  { to: '/tls', icon: Lock, label: 'TLS Scanner', requiresAuth: 'any' },
  { to: '/customers', icon: Users, label: 'Customers', requiresAuth: 'admin' },
  { to: '/nuclei', icon: Zap, label: 'Nuclei Scanner', requiresAuth: '' },
  { to: '/pentest', icon: ShieldAlert, label: 'PenTest Reports', requiresAuth: '' },
  { to: '/help', icon: HelpCircle, label: 'Help Center', requiresAuth: '' },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const { t, isRTL: rtl } = useLang();
  const [collapsed, setCollapsed] = useState(false);
  const [lang, setLang] = useState<'he' | 'en'>(() => (localStorage.getItem('mc_lang') as 'he' | 'en') || 'he');

  const toggleLang = () => {
    const next = lang === 'he' ? 'en' : 'he';
    setLang(next);
    localStorage.setItem('mc_lang', next);
    window.dispatchEvent(new Event('mc-lang-change'));
  };

  const canAccess = (item: typeof NAV_ITEMS[0]) => {
    if (!item.requiresAuth) return true;
    if (!user) return false;
    if (item.requiresAuth === 'admin') return user.role === 'ADMIN';
    if (item.requiresAuth === 'full') return user.role === 'ADMIN' || user.role === 'FULL_SCANS';
    return true;
  };

  const sidebarW = collapsed ? 'w-[60px]' : 'w-[240px]';

  return (
    <div className="min-h-screen bg-mc-bg0 text-mc-txt flex">
      {/* Sidebar */}
      <aside className={`${sidebarW} shrink-0 bg-mc-bg1 border-r border-mc-cardBorder/40 flex flex-col transition-all duration-200 fixed top-0 left-0 h-screen z-50`}>
        {/* Logo */}
        <div className="flex items-center gap-2.5 px-4 h-[56px] border-b border-mc-cardBorder/30">
          <NavLink to="/about" className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-mc-brand to-blue-600 flex items-center justify-center shadow-lg shadow-mc-brand/25 shrink-0">
              <Shield size={17} className="text-white" strokeWidth={2.5} />
            </div>
            {!collapsed && (
              <div className="leading-tight">
                <span className="text-white font-bold text-[14px] tracking-tight block">{t("Security Scanner")}</span>
                <span className="text-mc-brand text-[9px] font-mono tracking-[0.15em] uppercase">M-Challenge</span>
              </div>
            )}
          </NavLink>
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.filter(canAccess).map(n => (
            <NavLink key={n.to} to={n.to} end={n.to === '/about' || n.to === '/web'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium transition-all
                ${isActive
                  ? 'bg-mc-brand/12 text-mc-brand border border-mc-brand/20'
                  : 'text-mc-txt2 border border-transparent hover:text-white hover:bg-white/5'
                } ${collapsed ? 'justify-center px-0' : ''}`
              }
              title={collapsed ? n.label : undefined}>
              <n.icon size={18} className="shrink-0" />
              {!collapsed && <span>{t(n.label)}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Bottom section */}
        <div className="border-t border-mc-cardBorder/30 p-2 space-y-1">
          {/* IP Badge */}
          {!collapsed && (
            <div className="px-2 py-1.5">
              <ClientIpBadge />
            </div>
          )}

          {/* Lang toggle */}
          <button onClick={toggleLang}
            className={`flex items-center gap-2 w-full px-3 py-2 rounded-lg text-mc-txt3 hover:text-mc-txt2 hover:bg-mc-bg2 transition text-xs font-medium ${collapsed ? 'justify-center px-0' : ''}`}>
            <Languages size={15} />
            {!collapsed && (lang === 'he' ? 'עברית' : 'English')}
          </button>

          {/* Collapse toggle */}
          <button onClick={() => setCollapsed(!collapsed)}
            className={`flex items-center gap-2 w-full px-3 py-2 rounded-lg text-mc-txt3 hover:text-mc-txt2 hover:bg-mc-bg2 transition text-xs ${collapsed ? 'justify-center px-0' : ''}`}>
            {collapsed ? <PanelLeft size={15} /> : <PanelLeftClose size={15} />}
            {!collapsed && <span>{t('Collapse')}</span>}
          </button>

          {/* User */}
          {user ? (
            <div className="relative">
              <button onClick={() => setUserMenuOpen(!userMenuOpen)}
                className={`flex items-center gap-2 w-full px-2 py-2 rounded-xl hover:bg-mc-bg2 transition ${collapsed ? 'justify-center' : ''}`}>
                <div className="w-8 h-8 rounded-full bg-mc-brand/20 border border-mc-brand/30 flex items-center justify-center text-[12px] font-bold text-mc-brand shrink-0">
                  {(user.fullName || user.email)?.[0]?.toUpperCase() || 'U'}
                </div>
                {!collapsed && (
                  <>
                    <div className="text-left flex-1 min-w-0">
                      <div className="text-[12px] text-white font-medium leading-tight truncate">{user.fullName || 'Admin'}</div>
                      <div className="text-[10px] text-mc-txt3 leading-tight truncate">{user.email}</div>
                    </div>
                    <ChevronDown size={12} className="text-mc-txt3 shrink-0" />
                  </>
                )}
              </button>
              {userMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                  <div className="absolute left-0 bottom-full mb-1.5 w-52 bg-mc-card border border-mc-cardBorder rounded-xl shadow-2xl z-50 py-1 overflow-hidden">
                    <div className="px-3 py-2.5 border-b border-mc-cardBorder">
                      <div className="text-xs text-white font-semibold">{user.fullName || user.email}</div>
                      <div className="text-[10px] text-mc-txt3 mt-0.5">{user.email}</div>
                      <span className="mt-1.5 text-[9px] text-mc-brand bg-mc-brand/10 rounded-full px-2 py-0.5 inline-block font-medium">{user.role}</span>
                    </div>
                    <button onClick={() => { logout(); setUserMenuOpen(false); navigate('/login'); }}
                      className="w-full flex items-center gap-2 px-3 py-2.5 text-xs text-mc-rose hover:bg-mc-rose/8 transition">
                      <LogOut size={13} /> {t("Logout")}
                    </button>
                  </div>
                </>
              )}
            </div>
          ) : (
            <NavLink to="/login"
              className={`flex items-center justify-center gap-2 px-3 py-2.5 bg-mc-brand/15 border border-mc-brand/25 rounded-xl text-mc-brand text-xs font-semibold hover:bg-mc-brand/25 transition ${collapsed ? '' : 'w-full'}`}>
              {!collapsed && t('Sign In')}
              {collapsed && <LogOut size={15} />}
            </NavLink>
          )}
        </div>
      </aside>

      {/* Main content */}
      <main className={`flex-1 min-h-screen transition-all duration-200 ${collapsed ? 'ml-[60px]' : 'ml-[240px]'}`}>
        {children}
      </main>
    </div>
  );
}

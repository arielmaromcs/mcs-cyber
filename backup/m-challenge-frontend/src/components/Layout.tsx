import { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Globe, Mail, Crosshair, Target, Calendar, Settings, Info, User, LogOut } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const NAV = [
  { to: '/', icon: Globe, label: 'Web Scanner' },
  { to: '/email', icon: Mail, label: 'Email Scanner' },
  { to: '/threat', icon: Crosshair, label: 'Threat Intel' },
  { to: '/mitre', icon: Target, label: 'MITRE ATT&CK' },
  { to: '/schedules', icon: Calendar, label: 'Schedules' },
  { to: '/admin', icon: Settings, label: 'Admin' },
  { to: '/about', icon: Info, label: 'About' },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen bg-mc-bg0 text-mc-txt">
      {/* Sidebar */}
      <aside className="w-56 bg-mc-bg1 border-r border-mc-bg3 flex flex-col h-screen sticky top-0 shrink-0">
        {/* Logo */}
        <div className="px-4 py-4 border-b border-mc-bg3 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-mc-brand flex items-center justify-center">
            <Shield size={15} color="#fff" />
          </div>
          <div>
            <div className="font-mono font-bold text-[13px] text-white tracking-tight">M-CHALLENGE</div>
            <div className="text-[7px] text-mc-txt3 font-mono tracking-[0.12em] uppercase">Security Scanner</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-1.5 overflow-y-auto">
          {NAV.map(n => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 w-full px-3 py-2 rounded-md text-xs mb-0.5 transition-all
                ${isActive ? 'bg-mc-brand/10 text-mc-brand border border-mc-brand/20 font-semibold' : 'text-mc-txt3 border border-transparent hover:text-mc-txt2 hover:bg-mc-bg2'}`
              }>
              <n.icon size={14} />
              {n.label}
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="px-3 py-2.5 border-t border-mc-bg3">
          {user ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-[11px] text-mc-txt3 truncate">
                <User size={12} />{user.email}
              </div>
              <button onClick={logout} className="text-mc-txt3 hover:text-mc-rose transition-colors"><LogOut size={12} /></button>
            </div>
          ) : (
            <NavLink to="/login" className="flex items-center gap-2 text-[11px] text-mc-txt3 hover:text-mc-brand">
              <User size={12} />Sign in
            </NavLink>
          )}
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 overflow-y-auto h-screen">
        <div className="max-w-[1060px] mx-auto px-5 py-5">{children}</div>
      </main>
    </div>
  );
}

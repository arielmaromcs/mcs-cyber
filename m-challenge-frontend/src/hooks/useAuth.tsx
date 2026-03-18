import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api, setToken, clearToken } from '../lib/api';

interface User {
  id: string;
  email: string;
  fullName?: string;
  role: string;
  plan: string;
  scansRemaining: number;
}

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthCtx>({} as AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.whoami().then(r => { if (r.user) setUser(r.user); }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const r = await api.login(email, password);
    setToken(r.token);
    setUser(r.user);
  };

  const register = async (email: string, password: string, fullName?: string) => {
    const r = await api.register(email, password, fullName);
    setToken(r.token);
    setUser(r.user);
  };

  const logout = () => { clearToken(); setUser(null); };

  const refresh = async () => {
    try { const r = await api.whoami(); if (r.user) setUser(r.user); } catch {}
  };

  return <AuthContext.Provider value={{ user, loading, login, register, logout, refresh }}>{children}</AuthContext.Provider>;
}

export function useAuth() { return useContext(AuthContext); }

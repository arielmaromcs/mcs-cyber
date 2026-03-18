import { useLang } from '../hooks/useLang';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, LogIn } from 'lucide-react';
import { api, setToken } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { Card, Button, Input, Spinner } from '../components/ui';

export default function Login() {
  const { t } = useLang();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { refresh } = useAuth();
  const navigate = useNavigate();

  const submit = async () => {
    setError(''); setLoading(true);
    try {
      const data = isRegister
        ? await api.register(email, password, name)
        : await api.login(email, password);
      if (data.token) { setToken(data.token); await refresh(); navigate('/'); }
      else setError('Login failed');
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  return (
    <div className="hero-bg min-h-[calc(100vh-56px)] flex items-center justify-center px-4">
      <Card className="w-full max-w-sm p-6 animate-fadeInUp">
        <div className="text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-mc-brand/15 flex items-center justify-center mx-auto mb-3">
            <Shield size={24} className="text-mc-brand" />
          </div>
          <h1 className="text-lg font-bold text-white">{isRegister ? 'Create Account' : 'Sign In'}</h1>
          <p className="text-xs text-mc-txt3 mt-1">M-Challenge Security Scanner</p>
        </div>

        <div className="space-y-3">
          {isRegister && <Input label={t("Full Name")} value={name} onChange={(e: any) => setName(e.target.value)} placeholder="Your name" className="login-input" />}
          <Input label={t("Email")} type="email" value={email} onChange={(e: any) => setEmail(e.target.value)} placeholder="you@example.com" className="login-input" />
          <Input label={t("Password")} type="password" value={password} onChange={(e: any) => setPassword(e.target.value)} placeholder="••••••••" className="login-input" onKeyDown={(e: any) => e.key === 'Enter' && submit()} />
        </div>

        {error && <div className="mt-3 text-xs text-mc-rose">{error}</div>}

        <Button onClick={submit} disabled={loading} className="w-full mt-4" size="lg">
          {loading ? <Spinner size={14} /> : <><LogIn size={14} />{isRegister ? 'Register' : 'Sign In'}</>}
        </Button>

        <button onClick={() => setIsRegister(!isRegister)} className="w-full text-center text-xs text-mc-txt3 hover:text-mc-brand mt-3 transition">
          {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register"}
        </button>
      </Card>
    </div>
  );
}

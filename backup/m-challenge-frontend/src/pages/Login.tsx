import { useState } from 'react';
import { Shield, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Input, Button } from '../components/ui';

export default function LoginPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login, register } = useAuth();
  const nav = useNavigate();

  const submit = async () => {
    setLoading(true); setError('');
    try {
      if (isLogin) await login(email, password);
      else await register(email, password, name);
      nav('/');
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-mc-brand flex items-center justify-center mx-auto mb-4">
            <Shield size={24} color="#fff" />
          </div>
          <h1 className="font-mono font-bold text-xl text-white">M-CHALLENGE</h1>
          <p className="text-xs text-mc-txt3 mt-1">Security Scanner</p>
        </div>

        <div className="bg-mc-bg2 border border-mc-bg3 rounded-xl p-6 space-y-3">
          <div className="flex gap-1 p-1 bg-mc-bg1 rounded-lg mb-2">
            <button onClick={() => setIsLogin(true)} className={`flex-1 py-1.5 rounded-md text-xs font-medium ${isLogin ? 'bg-mc-brand/10 text-mc-brand' : 'text-mc-txt3'}`}>Sign in</button>
            <button onClick={() => setIsLogin(false)} className={`flex-1 py-1.5 rounded-md text-xs font-medium ${!isLogin ? 'bg-mc-brand/10 text-mc-brand' : 'text-mc-txt3'}`}>Register</button>
          </div>

          {!isLogin && <Input value={name} onChange={e => setName(e.target.value)} placeholder="Full name" />}
          <Input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" />
          <Input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="Password" />

          {error && <p className="text-rose-400 text-xs">{error}</p>}

          <Button onClick={submit} disabled={loading || !email || !password} className="w-full justify-center">
            {loading ? <Loader2 size={14} className="animate-spin-slow" /> : null}
            {isLogin ? 'Sign in' : 'Create account'}
          </Button>

          <div className="text-center text-[10px] text-mc-txt3 pt-2">
            Demo: admin@mchallenge.io / admin123
          </div>
        </div>
      </div>
    </div>
  );
}

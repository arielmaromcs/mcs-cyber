import { useState, useEffect } from 'react';
import { t as translate, setLanguage, getLang, isRTL, type Lang } from '../lib/i18n';

export function useLang() {
  const [, setTick] = useState(0);

  useEffect(() => {
    const handler = () => {
      const newLang = (localStorage.getItem('mc_lang') as Lang) || 'he';
      setLanguage(newLang);
      setTick(t => t + 1);
    };
    window.addEventListener('mc-lang-change', handler);
    return () => window.removeEventListener('mc-lang-change', handler);
  }, []);

  return { lang: getLang(), t: translate, isRTL: isRTL() };
}

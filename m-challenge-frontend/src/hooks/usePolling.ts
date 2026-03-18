import { useState, useEffect, useRef } from 'react';

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  enabled: boolean,
  onComplete?: (data: T) => void
) {
  const [data, setData] = useState<T | null>(null);
  const ref = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => {
    if (!enabled) { if (ref.current) clearInterval(ref.current); return; }

    const poll = async () => {
      try {
        const result = await fetcher();
        setData(result);
        const status = (result as any)?.status;
        if (status === 'COMPLETED' || status === 'FAILED') {
          if (ref.current) clearInterval(ref.current);
          onComplete?.(result);
        }
      } catch { /* silent */ }
    };

    poll(); // immediate first call
    ref.current = setInterval(poll, intervalMs);
    return () => { if (ref.current) clearInterval(ref.current); };
  }, [enabled]);

  return data;
}

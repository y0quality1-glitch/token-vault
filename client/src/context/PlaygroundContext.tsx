import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';

/**
 * Holds an agent API credential for the Access Playground IN MEMORY ONLY.
 * It is never written to localStorage, sessionStorage, cookies or URLs, and is
 * lost on page reload, mirroring how a real agent would hold its own secret.
 */
interface PlaygroundCredential {
  apiKey: string;
  agentId: string;
  agentName: string;
}

interface PlaygroundValue {
  credential: PlaygroundCredential | null;
  setCredential: (c: PlaygroundCredential | null) => void;
}

const Ctx = createContext<PlaygroundValue | null>(null);

export function PlaygroundProvider({ children }: { children: ReactNode }) {
  const [credential, setCredential] = useState<PlaygroundCredential | null>(null);
  const value = useMemo(() => ({ credential, setCredential }), [credential]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePlayground() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('usePlayground must be used inside PlaygroundProvider');
  return ctx;
}

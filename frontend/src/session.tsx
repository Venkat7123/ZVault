import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getMe, login, type Decision, type Me } from "./api";
import { sessionClock, type SessionClock } from "./timing";

// The token lives in memory only: no browser storage and no cookies.
// Reloading the page signs the employee out.

interface Session {
  token: string;
  user: Me;
  tokenExpiresAt: number;
}

export interface HistoryItem {
  id: number;
  question: string;
  decision: Decision;
  rowCount: number;
}

interface SessionApi {
  session: Session | null;
  clock: SessionClock | null;
  notice: string | null;
  history: HistoryItem[];
  signIn: (userId: string, password: string) => Promise<void>;
  signOut: (reason?: string) => void;
  touch: () => void;
  addHistory: (item: Omit<HistoryItem, "id">) => void;
  clearNotice: () => void;
}

const Ctx = createContext<SessionApi | null>(null);

const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "scroll", "touchstart"] as const;

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [clock, setClock] = useState<SessionClock | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const lastActivity = useRef(Date.now());
  const nextId = useRef(1);

  const touch = useCallback(() => {
    lastActivity.current = Date.now();
  }, []);

  const signOut = useCallback((reason?: string) => {
    setSession(null);
    setClock(null);
    setHistory([]);
    setNotice(reason ?? null);
  }, []);

  const signIn = useCallback(async (userId: string, password: string) => {
    const result = await login(userId, password);
    const user = await getMe(result.token);
    lastActivity.current = Date.now();
    setNotice(null);
    setHistory([]);
    setSession({ token: result.token, user, tokenExpiresAt: Date.now() + result.expires_in_minutes * 60_000 });
  }, []);

  // One-second tick: refresh both timers and enforce the idle and token limits.
  useEffect(() => {
    if (!session) return;
    const check = () => {
      const c = sessionClock(Date.now(), lastActivity.current, session.tokenExpiresAt);
      if (c.expired === "token") signOut("Your 15-minute token expired. Please sign in again.");
      else if (c.expired === "idle") signOut("Signed out after 15 minutes without activity.");
      else setClock(c);
    };
    check();
    const timer = window.setInterval(check, 1000);
    document.addEventListener("visibilitychange", check);
    for (const e of ACTIVITY_EVENTS) window.addEventListener(e, touch, { passive: true });
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", check);
      for (const e of ACTIVITY_EVENTS) window.removeEventListener(e, touch);
    };
  }, [session, signOut, touch]);

  const addHistory = useCallback((item: Omit<HistoryItem, "id">) => {
    setHistory((h) => [{ ...item, id: nextId.current++ }, ...h].slice(0, 50));
  }, []);

  const value = useMemo<SessionApi>(
    () => ({ session, clock, notice, history, signIn, signOut, touch, addHistory, clearNotice: () => setNotice(null) }),
    [session, clock, notice, history, signIn, signOut, touch, addHistory],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession must be used inside <SessionProvider>");
  return v;
}

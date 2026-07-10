import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, setCsrfToken } from "@/lib/api";

export interface User {
  id: number;
  username: string;
  role: string;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

async function refreshCsrf() {
  try {
    const { csrfToken } = await api.get<{ csrfToken: string }>("csrf");
    setCsrfToken(csrfToken);
  } catch {
    // The CSRF endpoint is unauthenticated; ignore transient failures.
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    (async () => {
      await refreshCsrf();
      try {
        const me = await api.get<User>("me");
        if (active) setUser(me);
      } catch {
        if (active) setUser(null);
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const me = await api.post<User>("login", { username, password });
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("logout");
    } catch {
      // Even if the request fails, drop local state.
    }
    setUser(null);
    await refreshCsrf();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

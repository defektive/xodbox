import { useEffect, useState, type FormEvent } from "react";
import { useAuth } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { apiBase } from "@/lib/base";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface ProvidersInfo {
  oidc?: { enabled: boolean; label?: string };
}

// initialSsoError surfaces the ?sso_error=… marker the OIDC callback redirects
// back with when an SSO attempt fails, so the user sees why rather than a blank
// login page.
function initialSsoError(): string | null {
  if (typeof window === "undefined") return null;
  const err = new URLSearchParams(window.location.search).get("sso_error");
  return err ? `SSO sign-in failed: ${err}` : null;
}

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(initialSsoError());
  const [busy, setBusy] = useState(false);
  const [ssoLabel, setSsoLabel] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api
      .get<ProvidersInfo>("auth/providers")
      .then((p) => {
        if (active && p.oidc?.enabled) {
          setSsoLabel(p.oidc.label || "Sign in with SSO");
        }
      })
      .catch(() => {
        // The providers endpoint is best-effort; if it fails we just render
        // the password form without an SSO button.
      });
    return () => {
      active = false;
    };
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "login failed");
      setBusy(false);
    }
  }

  function startSso() {
    // Full-page navigation: the server 302-redirects to the identity provider.
    window.location.href = apiBase + "auth/oidc/login";
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Sign in to xodbox</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
          {ssoLabel && (
            <>
              <div className="my-4 flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                or
                <span className="h-px flex-1 bg-border" />
              </div>
              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={startSso}
              >
                {ssoLabel}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

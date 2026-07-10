import { useAuth } from "@/lib/auth";
import Login from "@/pages/Login";
import Shell from "@/Shell";

// App is the auth gate: it shows a loading state while the session is checked,
// the login page when signed out, and the app shell when signed in.
export default function App() {
  const { user, loading, logout } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        Loading…
      </div>
    );
  }

  if (!user) {
    return <Login />;
  }

  return <Shell username={user.username} onLogout={() => void logout()} />;
}

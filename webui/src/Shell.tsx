import { NavLink, Route, Routes } from "react-router-dom";
import { cn } from "@/lib/utils";
import type { User } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Requests from "@/pages/Requests";
import RequestDetail from "@/pages/RequestDetail";
import Bots from "@/pages/Bots";
import Payloads from "@/pages/Payloads";
import PayloadEditor from "@/pages/PayloadEditor";
import Sinks from "@/pages/Sinks";
import SinkDetail from "@/pages/SinkDetail";
import Users from "@/pages/Users";
import ApiKeys from "@/pages/ApiKeys";
import Account from "@/pages/Account";

function Placeholder({ title }: { title: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        Coming soon.
      </CardContent>
    </Card>
  );
}

export default function Shell({
  user,
  onLogout,
}: {
  user: User;
  onLogout: () => void;
}) {
  const isAdmin = user.role === "admin";
  const nav = [
    { to: "/requests", label: "Requests" },
    { to: "/sinks", label: "Sinks" },
    { to: "/bots", label: "Bots" },
    { to: "/payloads", label: "Payloads" },
    ...(isAdmin ? [{ to: "/users", label: "Users" }] : []),
    { to: "/keys", label: "API Keys" },
    { to: "/account", label: "Account" },
  ];

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container flex h-14 items-center gap-6">
          <span className="font-semibold">xodbox</span>
          <nav className="flex items-center gap-4 text-sm">
            {nav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    "text-muted-foreground transition-colors hover:text-foreground",
                    isActive && "text-foreground",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="text-muted-foreground">{user.username}</span>
            <Button variant="outline" size="sm" onClick={onLogout}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main className="container py-6">
        <Routes>
          <Route path="/" element={<Requests />} />
          <Route path="/requests" element={<Requests />} />
          <Route path="/requests/:id" element={<RequestDetail />} />
          <Route path="/bots" element={<Bots />} />
          <Route path="/payloads" element={<Payloads />} />
          <Route path="/payloads/new" element={<PayloadEditor />} />
          <Route path="/payloads/:id" element={<PayloadEditor />} />
          <Route path="/sinks" element={<Sinks />} />
          <Route path="/sinks/:slug" element={<SinkDetail />} />
          <Route path="/users" element={<Users currentUserId={user.id} />} />
          <Route path="/keys" element={<ApiKeys />} />
          <Route path="/account" element={<Account />} />
          <Route path="*" element={<Placeholder title="Not found" />} />
        </Routes>
      </main>
    </div>
  );
}

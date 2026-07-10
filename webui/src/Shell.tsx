import { useState } from "react";
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

  const [menuOpen, setMenuOpen] = useState(false);

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "text-muted-foreground transition-colors hover:text-foreground",
      isActive && "text-foreground",
    );

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-20 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center gap-6">
          <span className="font-semibold">xodbox</span>

          {/* Desktop nav */}
          <nav className="hidden items-center gap-4 text-sm sm:flex">
            {nav.map((item) => (
              <NavLink key={item.to} to={item.to} className={linkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="hidden text-muted-foreground sm:inline">
              {user.username}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={onLogout}
              className="hidden sm:inline-flex"
            >
              Sign out
            </Button>

            {/* Mobile menu toggle */}
            <button
              type="button"
              className="-mr-1 inline-flex h-9 w-9 items-center justify-center rounded-md hover:bg-accent sm:hidden"
              aria-label="Toggle menu"
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              >
                {menuOpen ? (
                  <path d="M6 6l12 12M18 6L6 18" />
                ) : (
                  <path d="M4 7h16M4 12h16M4 17h16" />
                )}
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile nav drawer */}
        {menuOpen && (
          <nav className="border-t bg-background sm:hidden">
            <div className="container flex flex-col py-2">
              {nav.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={() => setMenuOpen(false)}
                  className={(s) => cn(linkClass(s), "py-2.5")}
                >
                  {item.label}
                </NavLink>
              ))}
              <div className="mt-2 flex items-center justify-between border-t pt-3">
                <span className="text-muted-foreground">{user.username}</span>
                <Button variant="outline" size="sm" onClick={onLogout}>
                  Sign out
                </Button>
              </div>
            </div>
          </nav>
        )}
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

import { NavLink, Route, Routes } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// Phase 1 ships the app shell + routing. Real pages (request log, payloads,
// bots, users, API keys) land in later phases; they render as placeholders
// for now so the mount/embed/build pipeline can be exercised end to end.
const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/requests", label: "Requests" },
  { to: "/bots", label: "Bots" },
  { to: "/payloads", label: "Payloads" },
  { to: "/users", label: "Users" },
  { to: "/keys", label: "API Keys" },
];

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

export default function App() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container flex h-14 items-center gap-6">
          <span className="font-semibold">xodbox</span>
          <nav className="flex items-center gap-4 text-sm">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
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
        </div>
      </header>
      <main className="container py-6">
        <Routes>
          <Route path="/" element={<Placeholder title="Dashboard" />} />
          <Route path="/requests" element={<Placeholder title="Requests" />} />
          <Route path="/bots" element={<Placeholder title="Bots" />} />
          <Route path="/payloads" element={<Placeholder title="Payloads" />} />
          <Route path="/users" element={<Placeholder title="Users" />} />
          <Route path="/keys" element={<Placeholder title="API Keys" />} />
          <Route path="*" element={<Placeholder title="Not found" />} />
        </Routes>
      </main>
    </div>
  );
}

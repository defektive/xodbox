import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { mockAuth } = vi.hoisted(() => ({
  mockAuth: {
    user: null as { id: number; username: string; role: string } | null,
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock("@/lib/auth", () => ({
  useAuth: () => mockAuth,
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
}));

import App from "@/App";

function renderApp() {
  return render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
}

describe("App auth gate", () => {
  it("shows the login page when signed out", () => {
    mockAuth.user = null;
    mockAuth.loading = false;
    renderApp();
    expect(screen.getByText("Sign in to xodbox")).toBeInTheDocument();
  });

  it("shows a loading state while the session is checked", () => {
    mockAuth.user = null;
    mockAuth.loading = true;
    renderApp();
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows the app shell when signed in", () => {
    mockAuth.user = { id: 1, username: "alice", role: "admin" };
    mockAuth.loading = false;
    renderApp();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Requests" })).toBeInTheDocument();
  });
});

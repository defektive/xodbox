import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Shell from "@/Shell";

const user = { id: 1, username: "alice", role: "admin" };

function renderAt(path: string, onLogout = vi.fn()) {
  getMock.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Shell user={user} onLogout={onLogout} />
    </MemoryRouter>,
  );
}

describe("Shell", () => {
  it("renders nav, username, and the requests view by default", () => {
    renderAt("/");
    expect(screen.getByText("xodbox")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Requests" })).toBeInTheDocument();
    const main = screen.getByRole("main");
    expect(within(main).getByText("Method")).toBeInTheDocument();
  });

  it("routes to the bots view", () => {
    renderAt("/bots");
    const main = screen.getByRole("main");
    expect(within(main).getByText("Source IP")).toBeInTheDocument();
  });

  it("calls onLogout when Sign out is clicked", () => {
    const onLogout = vi.fn();
    renderAt("/", onLogout);
    screen.getByRole("button", { name: "Sign out" }).click();
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("toggles the mobile nav drawer", () => {
    renderAt("/");
    // Only the desktop nav is rendered until the menu opens.
    expect(screen.getAllByRole("link", { name: "Requests" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Toggle menu" }));
    // Opening the drawer adds a second copy of each nav link.
    expect(screen.getAllByRole("link", { name: "Requests" })).toHaveLength(2);
  });

  it("hides the Users nav for non-admins", () => {
    getMock.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    render(
      <MemoryRouter>
        <Shell
          user={{ id: 2, username: "bob", role: "user" }}
          onLogout={vi.fn()}
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.getByRole("link", { name: "API Keys" })).toBeInTheDocument();
  });
});

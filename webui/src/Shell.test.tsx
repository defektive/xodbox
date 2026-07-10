import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import Shell from "@/Shell";

function renderAt(path: string, onLogout = vi.fn()) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Shell username="alice" onLogout={onLogout} />
    </MemoryRouter>,
  );
}

describe("Shell", () => {
  it("renders nav, username, and dashboard by default", () => {
    renderAt("/");
    expect(screen.getByText("xodbox")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Requests" })).toBeInTheDocument();
    const main = screen.getByRole("main");
    expect(within(main).getByText("Dashboard")).toBeInTheDocument();
  });

  it("routes to the requests placeholder", () => {
    renderAt("/requests");
    const main = screen.getByRole("main");
    expect(within(main).getByText("Requests")).toBeInTheDocument();
  });

  it("calls onLogout when Sign out is clicked", () => {
    const onLogout = vi.fn();
    renderAt("/", onLogout);
    screen.getByRole("button", { name: "Sign out" }).click();
    expect(onLogout).toHaveBeenCalledTimes(1);
  });
});

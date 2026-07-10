import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "@/App";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App shell", () => {
  it("renders the nav and dashboard by default", () => {
    renderAt("/");
    expect(screen.getByText("xodbox")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Requests" })).toBeInTheDocument();
    // Page content lives in <main>; scope to it to avoid matching nav links.
    const main = screen.getByRole("main");
    expect(within(main).getByText("Dashboard")).toBeInTheDocument();
    expect(within(main).getByText("Coming soon.")).toBeInTheDocument();
  });

  it("routes to the requests placeholder", () => {
    renderAt("/requests");
    const main = screen.getByRole("main");
    expect(within(main).getByText("Requests")).toBeInTheDocument();
  });
});

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Bots from "@/pages/Bots";

describe("Bots", () => {
  it("lists bot sources with a link to their events", async () => {
    getMock.mockResolvedValue([
      { remote_addr: "9.9.9.9", total: 42, minute_group: 0 },
    ]);
    render(
      <MemoryRouter>
        <Bots />
      </MemoryRouter>,
    );
    expect(await screen.findByText("9.9.9.9")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "view events" })).toHaveAttribute(
      "href",
      "/events?remote=9.9.9.9",
    );
  });
});

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Requests from "@/pages/Requests";

describe("Requests", () => {
  it("renders interaction rows", async () => {
    getMock.mockResolvedValue({
      items: [
        {
          id: 7,
          created_at: new Date().toISOString(),
          remote_addr: "1.2.3.4",
          remote_port: "5000",
          handler: "httpx",
          request_type: "POST",
          request_target: "/l/beacon",
          protocol: "http",
          user_agent: "",
        },
      ],
      total: 1,
      limit: 50,
      offset: 0,
    });

    render(
      <MemoryRouter>
        <Requests />
      </MemoryRouter>,
    );

    const link = await screen.findByRole("link", { name: "/l/beacon" });
    expect(link).toHaveAttribute("href", "/requests/7");
    expect(screen.getByText("1.2.3.4")).toBeInTheDocument();
    expect(screen.getByText("POST")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    getMock.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    render(
      <MemoryRouter>
        <Requests />
      </MemoryRouter>,
    );
    expect(await screen.findByText("No requests.")).toBeInTheDocument();
  });
});

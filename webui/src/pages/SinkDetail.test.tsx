import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock, post: vi.fn(), del: vi.fn() },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import SinkDetail from "@/pages/SinkDetail";

describe("SinkDetail", () => {
  it("shows the sink description and its events newest first", async () => {
    getMock.mockResolvedValue({
      slug: "abc123",
      description: "prod ssrf beacon",
      created_at: new Date().toISOString(),
      event_count: 2,
      total: 2,
      limit: 50,
      offset: 0,
      events: [
        {
          id: 9,
          created_at: new Date().toISOString(),
          remote_addr: "10.0.0.5",
          remote_port: "443",
          handler: "dns",
          request_type: "A",
          request_target: "abc123.oob.example.",
          protocol: "dns",
          user_agent: "",
        },
        {
          id: 8,
          created_at: new Date().toISOString(),
          remote_addr: "10.0.0.5",
          remote_port: "80",
          handler: "httpx",
          request_type: "GET",
          request_target: "/abc123/beacon",
          protocol: "http",
          user_agent: "",
        },
      ],
    });

    render(
      <MemoryRouter initialEntries={["/sinks/abc123"]}>
        <Routes>
          <Route path="/sinks/:slug" element={<SinkDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("prod ssrf beacon")).toBeInTheDocument();

    // Both events render, linking to their request detail.
    const dnsLink = screen.getByRole("link", { name: "abc123.oob.example." });
    expect(dnsLink).toHaveAttribute("href", "/requests/9");
    const httpLink = screen.getByRole("link", { name: "/abc123/beacon" });
    expect(httpLink).toHaveAttribute("href", "/requests/8");

    // Slug is fetched from the URL param.
    expect(getMock).toHaveBeenCalledWith("sinks/abc123");
  });
});

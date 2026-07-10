import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MockEventSource } from "@/test/setup";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Events from "@/pages/Events";

beforeEach(() => MockEventSource.reset());

describe("Events", () => {
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
        <Events />
      </MemoryRouter>,
    );

    const link = await screen.findByRole("link", { name: "/l/beacon" });
    expect(link).toHaveAttribute("href", "/events/7");
    expect(screen.getByText("1.2.3.4")).toBeInTheDocument();
    expect(screen.getByText("POST")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    getMock.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    expect(await screen.findByText("No events.")).toBeInTheDocument();
  });

  it("prepends live interactions from the SSE stream", async () => {
    getMock.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    // The stream connection was opened.
    expect(await screen.findByText("No events.")).toBeInTheDocument();
    const es =
      MockEventSource.instances[MockEventSource.instances.length - 1];
    expect(es.url).toContain("stream");

    act(() => {
      es.emit("interaction", {
        id: 42,
        created_at: new Date().toISOString(),
        remote_addr: "9.9.9.9",
        remote_port: "1",
        handler: "dns",
        request_type: "A",
        request_target: "live.example.",
        protocol: "dns",
        user_agent: "",
      });
    });

    expect(
      await screen.findByRole("link", { name: "live.example." }),
    ).toHaveAttribute("href", "/events/42");
  });
});

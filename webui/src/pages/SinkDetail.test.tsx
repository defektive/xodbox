import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock, putMock } = vi.hoisted(() => ({
  getMock: vi.fn(),
  putMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { get: getMock, post: vi.fn(), put: putMock, del: vi.fn() },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import SinkDetail from "@/pages/SinkDetail";

function renderSink() {
  return render(
    <MemoryRouter initialEntries={["/sinks/abc123"]}>
      <Routes>
        <Route path="/sinks/:slug" element={<SinkDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("SinkDetail", () => {
  it("renders an event timeline with full details, hiding empty replays", async () => {
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
          // SMB auth capture: no raw HTTP request, no replay — only a body
          // (the hash). The empty Replay and Raw request blocks must be hidden.
          id: 9,
          created_at: new Date().toISOString(),
          remote_addr: "10.0.0.5",
          remote_port: "445",
          handler: "smb",
          request_type: "Auth",
          request_target: "CORP\\alice",
          protocol: "smb",
          user_agent: "",
          headers: "",
          body: "alice::CORP:1122...hashcatline",
          curl: "",
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
          headers: "GET /abc123/beacon HTTP/1.1\r\nHost: h\r\n\r\n",
          body: "",
          curl: "curl 'http://h/abc123/beacon'",
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

    // Only the httpx event has a raw request and a replay; the SMB event's
    // empty blocks are hidden (not rendered as empty code boxes).
    expect(screen.getAllByRole("button", { name: "Copy raw request" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Copy as curl" })).toHaveLength(1);
    expect(screen.getByText(/GET \/abc123\/beacon HTTP/)).toBeInTheDocument();

    // The SMB event still shows its captured hash (a body).
    expect(screen.getAllByRole("button", { name: "Copy body" })).toHaveLength(1);
    expect(screen.getByText(/hashcatline/)).toBeInTheDocument();

    // Each entry links to its full request detail.
    const opens = screen.getAllByRole("link", { name: /open/ });
    expect(opens[0]).toHaveAttribute("href", "/events/9");
    expect(opens[1]).toHaveAttribute("href", "/events/8");

    // Slug is fetched from the URL param.
    expect(getMock).toHaveBeenCalledWith("sinks/abc123");
  });

  it("copies an HTTP link to the slug", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    getMock.mockResolvedValue({
      slug: "abc123",
      description: "",
      created_at: new Date().toISOString(),
      event_count: 0,
      total: 0,
      limit: 50,
      offset: 0,
      events: [],
    });

    renderSink();

    fireEvent.click(await screen.findByRole("button", { name: "Copy HTTP link" }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        `${window.location.origin}/abc123`,
      ),
    );
    // Button flips to the copied state.
    expect(
      await screen.findByRole("button", { name: "Copied!" }),
    ).toBeInTheDocument();
  });

  it("edits the sink description", async () => {
    getMock.mockResolvedValue({
      slug: "abc123",
      description: "old",
      created_at: new Date().toISOString(),
      event_count: 0,
      total: 0,
      limit: 50,
      offset: 0,
      events: [],
    });
    putMock.mockResolvedValue({
      slug: "abc123",
      description: "updated purpose",
      created_at: new Date().toISOString(),
      event_count: 0,
    });

    renderSink();

    // Enter edit mode, change the text, save.
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    fireEvent.change(screen.getByLabelText("Sink description"), {
      target: { value: "updated purpose" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(putMock).toHaveBeenCalledWith("sinks/abc123", {
        description: "updated purpose",
      }),
    );
    // The new description is shown after saving.
    expect(await screen.findByText("updated purpose")).toBeInTheDocument();
  });
});

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import EventDetail from "@/pages/EventDetail";

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/events/7"]}>
      <Routes>
        <Route path="/events/:id" element={<EventDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("EventDetail", () => {
  it("shows the request and copies the curl command", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    getMock.mockResolvedValue({
      id: 7,
      created_at: new Date().toISOString(),
      remote_addr: "1.2.3.4",
      remote_port: "5000",
      handler: "httpx",
      request_type: "POST",
      request_target: "/l/beacon",
      protocol: "http",
      user_agent: "",
      headers: "POST /l/beacon HTTP/1.1\r\nHost: h\r\n\r\n",
      body: "hello",
      curl: "curl -X POST 'http://h/l/beacon' --data-raw 'hello'",
    });

    renderDetail();

    expect(
      await screen.findByText("curl -X POST 'http://h/l/beacon' --data-raw 'hello'"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy as curl" }));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        "curl -X POST 'http://h/l/beacon' --data-raw 'hello'",
      ),
    );
  });

  it("links to the raw body download", async () => {
    getMock.mockResolvedValue({
      id: 7,
      created_at: new Date().toISOString(),
      remote_addr: "1.2.3.4",
      remote_port: "5000",
      handler: "tcp",
      request_type: "",
      request_target: "",
      protocol: "tcp",
      user_agent: "",
      headers: "",
      body: "00000000  de ad be ef",
      has_binary_body: true,
      body_size: 4,
      curl: "",
    });

    renderDetail();

    const link = await screen.findByRole("link", { name: "Download raw body" });
    expect(link.getAttribute("href")).toMatch(/interactions\/7\/body$/);
    expect(link).toHaveAttribute("download", "interaction-7-body.bin");
  });
});

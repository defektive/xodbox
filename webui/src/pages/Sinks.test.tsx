import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock, postMock, delMock } = vi.hoisted(() => ({
  getMock: vi.fn(),
  postMock: vi.fn(),
  delMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { get: getMock, post: postMock, del: delMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Sinks from "@/pages/Sinks";

describe("Sinks", () => {
  it("lists sinks with hit counts", async () => {
    getMock.mockResolvedValue([
      {
        slug: "abc123",
        description: "prod ssrf",
        created_at: new Date().toISOString(),
        event_count: 4,
      },
    ]);

    render(
      <MemoryRouter>
        <Sinks />
      </MemoryRouter>,
    );

    const row = (await screen.findByText("abc123")).closest("tr")!;
    expect(within(row).getByText("prod ssrf")).toBeInTheDocument();
    expect(within(row).getByText("4")).toBeInTheDocument();
  });

  it("creates a sink (slug optional) and reloads", async () => {
    getMock.mockResolvedValue([]);
    postMock.mockResolvedValue({
      slug: "generated",
      description: "d",
      created_at: new Date().toISOString(),
      event_count: 0,
    });

    render(
      <MemoryRouter>
        <Sinks />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "my sink" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create sink" }));

    expect(postMock).toHaveBeenCalledWith("sinks", {
      slug: "",
      description: "my sink",
    });
  });
});

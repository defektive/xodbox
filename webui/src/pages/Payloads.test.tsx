import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { get: getMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Payloads from "@/pages/Payloads";

describe("Payloads", () => {
  it("lists payloads with a link to edit", async () => {
    getMock.mockResolvedValue([
      {
        id: 3,
        name: "redirect",
        description: "",
        type: "HTTPX",
        pattern: "^/r",
        is_final: true,
        sort_order: 10,
        internal_function: "",
        headers: null,
        body: "",
        status_code: "302",
      },
    ]);
    render(
      <MemoryRouter>
        <Payloads />
      </MemoryRouter>,
    );
    const link = await screen.findByRole("link", { name: "redirect" });
    expect(link).toHaveAttribute("href", "/payloads/3");
    expect(screen.getByText("^/r")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "New payload" }),
    ).toBeInTheDocument();
  });
});

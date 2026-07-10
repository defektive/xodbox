import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const { getMock, postMock } = vi.hoisted(() => ({
  getMock: vi.fn(),
  postMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { get: getMock, post: postMock, del: vi.fn() },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import ApiKeys from "@/pages/ApiKeys";

describe("ApiKeys", () => {
  it("creates a key and shows the secret once", async () => {
    getMock.mockResolvedValue([]);
    postMock.mockResolvedValue({
      id: 5,
      name: "ci",
      prefix: "xdbx_ab",
      created_at: new Date().toISOString(),
      last_used_at: null,
      expires_at: null,
      key: "xdbx_secretkeyvalue",
    });

    render(
      <MemoryRouter>
        <ApiKeys />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Key name"), {
      target: { value: "ci" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    expect(await screen.findByText("xdbx_secretkeyvalue")).toBeInTheDocument();
  });
});

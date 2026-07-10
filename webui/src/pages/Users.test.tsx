import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

import Users from "@/pages/Users";

describe("Users", () => {
  it("lists users and creates a new one", async () => {
    getMock.mockResolvedValue([
      { id: 1, username: "admin", role: "admin" },
      { id: 2, username: "bob", role: "user" },
    ]);
    postMock.mockResolvedValue({ id: 3, username: "carol", role: "user" });

    render(
      <MemoryRouter>
        <Users currentUserId={1} />
      </MemoryRouter>,
    );

    expect(await screen.findByText("bob")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "carol" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "a-strong-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));

    await waitFor(() =>
      expect(postMock).toHaveBeenCalledWith(
        "users",
        expect.objectContaining({ username: "carol", role: "user" }),
      ),
    );
  });
});

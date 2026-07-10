import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const { loginMock } = vi.hoisted(() => ({ loginMock: vi.fn() }));

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    login: loginMock,
    user: null,
    loading: false,
    logout: vi.fn(),
  }),
}));

import Login from "@/pages/Login";

describe("Login", () => {
  it("submits the entered credentials", async () => {
    loginMock.mockResolvedValueOnce(undefined);
    render(<Login />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "s3cret-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() =>
      expect(loginMock).toHaveBeenCalledWith("alice", "s3cret-password"),
    );
  });

  it("shows an error when login fails", async () => {
    loginMock.mockRejectedValueOnce(new Error("nope"));
    render(<Login />);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toBeInTheDocument(),
    );
  });
});

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { loginMock, getMock } = vi.hoisted(() => ({
  loginMock: vi.fn(),
  getMock: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    login: loginMock,
    user: null,
    loading: false,
    logout: vi.fn(),
  }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, get: getMock } };
});

import Login from "@/pages/Login";

describe("Login", () => {
  beforeEach(() => {
    loginMock.mockReset();
    // Default: SSO disabled.
    getMock.mockReset().mockResolvedValue({ oidc: { enabled: false } });
  });

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

  it("renders an SSO button when OIDC is enabled", async () => {
    getMock.mockResolvedValue({ oidc: { enabled: true, label: "Sign in with Okta" } });
    render(<Login />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Sign in with Okta" }),
      ).toBeInTheDocument(),
    );
  });

  it("hides the SSO button when OIDC is disabled", async () => {
    render(<Login />);
    // Let the providers fetch resolve.
    await screen.findByRole("button", { name: "Sign in" });
    expect(
      screen.queryByRole("button", { name: /SSO/i }),
    ).not.toBeInTheDocument();
  });
});

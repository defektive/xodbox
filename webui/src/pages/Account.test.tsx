import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const { postMock } = vi.hoisted(() => ({ postMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { post: postMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import Account from "@/pages/Account";

describe("Account", () => {
  it("submits a password change", async () => {
    postMock.mockResolvedValue(undefined);
    render(<Account />);

    fireEvent.change(screen.getByLabelText("Current password"), {
      target: { value: "old-password" },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "new-strong-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Update password" }));

    await waitFor(() =>
      expect(postMock).toHaveBeenCalledWith("account/password", {
        current: "old-password",
        new: "new-strong-password",
      }),
    );
    expect(await screen.findByText("Password updated.")).toBeInTheDocument();
  });
});

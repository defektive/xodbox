import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getMock, postMock, putMock, delMock } = vi.hoisted(() => ({
  getMock: vi.fn(),
  postMock: vi.fn(),
  putMock: vi.fn(),
  delMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { get: getMock, post: postMock, put: putMock, del: delMock },
  ApiError: class ApiError extends Error {},
  setCsrfToken: vi.fn(),
}));

import PayloadEditor from "@/pages/PayloadEditor";

function renderNew() {
  return render(
    <MemoryRouter initialEntries={["/payloads/new"]}>
      <Routes>
        <Route path="/payloads/new" element={<PayloadEditor />} />
        <Route path="/payloads" element={<div>list</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("PayloadEditor", () => {
  beforeEach(() => {
    getMock.mockReset();
    postMock.mockReset();
    putMock.mockReset();
    delMock.mockReset();
  });

  it("creates a payload", async () => {
    postMock.mockResolvedValueOnce({});
    renderNew();
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "p1" },
    });
    fireEvent.change(screen.getByLabelText("Pattern (regex)"), {
      target: { value: "^/x" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(postMock).toHaveBeenCalled());
    const [path, body] = postMock.mock.calls[0];
    expect(path).toBe("payloads");
    expect(body.name).toBe("p1");
    expect(body.pattern).toBe("^/x");
  });

  it("blocks saving on an invalid regex", () => {
    renderNew();
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "p1" },
    });
    fireEvent.change(screen.getByLabelText("Pattern (regex)"), {
      target: { value: "[" },
    });
    // A validation error is shown and Save is disabled.
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(postMock).not.toHaveBeenCalled();
  });
});

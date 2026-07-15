import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import Config from "./Config";

const mockConfig = {
  configPath: "/etc/xodbox.yaml",
  defaults: { server_name: "test.example.com" },
  handlers: [{ handler: "httpx", listener: ":8080" }],
  notifiers: [{ notifier: "app_log" }],
  workers: [{ worker: "certbot" }],
};

const mockSchema = {
  handlers: ["httpx", "dns", "ftp", "smtp", "ssh", "tcp", "smb"],
  notifiers: ["app_log", "slack", "discord", "webhook"],
  workers: ["certbot"],
};

function wrap(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  globalThis.fetch = fetchMock;
});

afterEach(() => {
  vi.restoreAllMocks();
});

function respondWith(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: () => Promise.resolve(data),
  });
}

function setupFetchForLoad() {
  fetchMock.mockImplementation((url: string) => {
    if (url.includes("/config/schema")) return respondWith(mockSchema);
    if (url.includes("/config")) return respondWith(mockConfig);
    return respondWith({}, 404);
  });
}

describe("Config page", () => {
  it("shows loading state initially", () => {
    fetchMock.mockImplementation(() => new Promise(() => {}));
    wrap(<Config />);
    expect(screen.getByText(/Loading config/)).toBeInTheDocument();
  });

  it("shows error when fetch fails", async () => {
    fetchMock.mockImplementation(() =>
      respondWith({ error: "forbidden" }, 403),
    );
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("forbidden");
    });
  });

  it("renders the editor with fetched data", async () => {
    setupFetchForLoad();
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByDisplayValue("server_name")).toBeInTheDocument();
    });
    expect(screen.getByDisplayValue("test.example.com")).toBeInTheDocument();
    expect(screen.getByText("Handlers")).toBeInTheDocument();
    expect(screen.getByText("Notifiers")).toBeInTheDocument();
    expect(screen.getByText("Workers")).toBeInTheDocument();
  });

  it("shows config file path", async () => {
    setupFetchForLoad();
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByText(/\/etc\/xodbox\.yaml/)).toBeInTheDocument();
    });
  });

  it("switches to YAML tab", async () => {
    setupFetchForLoad();
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByDisplayValue("server_name")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: "YAML" }));
    expect(screen.getByLabelText("Raw YAML")).toBeInTheDocument();
  });

  it("shows success banner after save", async () => {
    setupFetchForLoad();
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByDisplayValue("server_name")).toBeInTheDocument();
    });

    fetchMock.mockImplementation((_url: string, opts?: RequestInit) => {
      if (opts?.method === "PUT") {
        return respondWith({ saved: true, reloading: true });
      }
      return respondWith(mockConfig);
    });

    fireEvent.click(screen.getByRole("button", { name: "Save config" }));
    await waitFor(() => {
      expect(screen.getByText(/Config saved/)).toBeInTheDocument();
    });
  });

  it("shows validation error from server", async () => {
    setupFetchForLoad();
    wrap(<Config />);
    await waitFor(() => {
      expect(screen.getByDisplayValue("server_name")).toBeInTheDocument();
    });

    fetchMock.mockImplementation((_url: string, opts?: RequestInit) => {
      if (opts?.method === "PUT") {
        return respondWith({ error: "unknown handler: bad" }, 400);
      }
      return respondWith(mockConfig);
    });

    fireEvent.click(screen.getByRole("button", { name: "Save config" }));
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        "unknown handler: bad",
      );
    });
  });
});

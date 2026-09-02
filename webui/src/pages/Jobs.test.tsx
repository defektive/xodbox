import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Jobs, { type WorkerStatus } from "./Jobs";
import { api } from "@/lib/api";

function renderJobs() {
  return render(
    <MemoryRouter>
      <Jobs />
    </MemoryRouter>,
  );
}

const idleWorker: WorkerStatus = {
  name: "purge",
  schedule: "@daily",
  running: false,
  last_run: "2026-09-01T10:00:00Z",
  last_duration_ms: 1500,
  next_run: "2026-09-02T00:00:00Z",
};

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Jobs", () => {
  it("lists configured jobs with their schedule", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ workers: [idleWorker] });

    renderJobs();

    expect(await screen.findByText("purge")).toBeInTheDocument();
    expect(screen.getByText("@daily")).toBeInTheDocument();
    expect(screen.getByText("took 1.5s")).toBeInTheDocument();
  });

  it("explains that nothing will run when no jobs are configured", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ workers: [] });

    renderJobs();

    expect(
      await screen.findByText(/No background jobs are configured/i),
    ).toBeInTheDocument();
  });

  it("posts to the run endpoint when Run now is clicked", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ workers: [idleWorker] });
    const post = vi.spyOn(api, "post").mockResolvedValue({
      started: true,
      worker: "purge",
    });

    renderJobs();
    fireEvent.click(await screen.findByRole("button", { name: "Run now" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("workers/purge/run"));
  });

  it("disables the button and shows progress while a job is running", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      workers: [{ ...idleWorker, running: true }],
    });

    renderJobs();

    const btn = await screen.findByRole("button", { name: "Running…" });
    expect(btn).toBeDisabled();
    expect(screen.getByText("running…")).toBeInTheDocument();
  });

  it("surfaces a failed run so a busy or unknown job is visible", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ workers: [idleWorker] });
    vi.spyOn(api, "post").mockRejectedValue(
      Object.assign(new Error("worker purge is already running"), {
        status: 409,
      }),
    );

    renderJobs();
    fireEvent.click(await screen.findByRole("button", { name: "Run now" }));

    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("reports the last run's error", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      workers: [{ ...idleWorker, last_error: "vacuum failed: disk full" }],
    });

    renderJobs();

    expect(
      await screen.findByText("vacuum failed: disk full"),
    ).toBeInTheDocument();
  });

  it("distinguishes a job that has never run from one that is unscheduled", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      workers: [{ name: "purge", schedule: "@daily", running: false }],
    });

    renderJobs();

    expect(await screen.findByText("never")).toBeInTheDocument();
    expect(screen.getByText("not scheduled")).toBeInTheDocument();
  });
});

import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export interface WorkerStatus {
  name: string;
  schedule: string;
  running: boolean;
  last_run?: string;
  last_duration_ms?: number;
  last_error?: string;
  next_run?: string;
}

// While a job is in flight the server has no way to push progress, so poll.
const POLL_MS = 2000;

function formatWhen(iso?: string): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function formatDuration(ms?: number): string {
  if (ms === undefined || ms === null) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

export default function Jobs() {
  const [workers, setWorkers] = useState<WorkerStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  // Kept in a ref so the polling effect doesn't have to re-subscribe every
  // time the data changes.
  const anyRunning = useRef(false);
  anyRunning.current = (workers ?? []).some((w) => w.running);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ workers: WorkerStatus[] }>("workers");
      setWorkers(res?.workers ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const id = setInterval(() => {
      // Only poll while something is actually running; an idle Jobs page
      // shouldn't hammer the server.
      if (anyRunning.current) void load();
    }, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  async function onRun(name: string) {
    setActionError(null);
    setStarting(name);
    try {
      await api.post(`workers/${encodeURIComponent(name)}/run`);
      // The server replies 202 the moment the run is accepted; reload to pick
      // up the running state, and the poll above takes it from there.
      await load();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "run failed");
    } finally {
      setStarting(null);
    }
  }

  if (loading) {
    return <p className="text-muted-foreground">Loading jobs…</p>;
  }
  if (error) {
    return (
      <p className="text-destructive" role="alert">
        {error}
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-medium">Background jobs</h1>
        <p className="text-sm text-muted-foreground">
          Jobs configured under <code>workers:</code> run on their schedule. Run
          one now to apply it immediately.
        </p>
      </div>

      {actionError && (
        <p className="text-sm text-destructive" role="alert">
          {actionError}
        </p>
      )}

      {workers && workers.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No background jobs are configured, so none will ever run. Add one
          under Workers on the <Link to="/config" className="underline">Config</Link>{" "}
          page.
        </p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Job</TableHead>
              <TableHead>Schedule</TableHead>
              <TableHead>Last run</TableHead>
              <TableHead>Next run</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(workers ?? []).map((w) => (
              <TableRow key={w.name}>
                <TableCell className="font-medium">
                  {w.name}
                  {w.running && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      running…
                    </span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {w.schedule}
                </TableCell>
                <TableCell className="text-xs">
                  <div>{formatWhen(w.last_run)}</div>
                  {w.last_run && w.last_duration_ms !== undefined && (
                    <div className="text-muted-foreground">
                      took {formatDuration(w.last_duration_ms)}
                    </div>
                  )}
                  {w.last_error && (
                    <div className="text-destructive" role="alert">
                      {w.last_error}
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-xs">
                  {w.next_run ? formatWhen(w.next_run) : "not scheduled"}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={w.running || starting === w.name}
                    onClick={() => void onRun(w.name)}
                  >
                    {w.running || starting === w.name ? "Running…" : "Run now"}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

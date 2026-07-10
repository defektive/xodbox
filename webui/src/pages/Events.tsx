import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import { useInteractionStream } from "@/lib/useStream";
import type { InteractionPage, InteractionSummary } from "@/lib/types";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const FILTERS = [
  { key: "target", label: "Path" },
  { key: "remote", label: "Source IP" },
  { key: "handler", label: "Handler" },
] as const;

export default function Events() {
  const [params, setParams] = useSearchParams();

  const query = new URLSearchParams();
  for (const { key } of FILTERS) {
    const v = params.get(key);
    if (v) query.set(key, v);
  }
  const qs = query.toString();
  const { data, error, loading } = useApi<InteractionPage>(
    "interactions" + (qs ? "?" + qs : ""),
  );

  // Seed from the fetched page, then prepend live events. The server applies
  // the same filters to the stream, so anything received belongs in this view.
  const [items, setItems] = useState<InteractionSummary[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  // Track ids we've already shown so a duplicate stream frame (reconnect,
  // fetch/stream overlap) doesn't double-count or re-insert.
  const seen = useRef<Set<number>>(new Set());
  useEffect(() => {
    const initial = data?.items ?? [];
    setItems(initial);
    setLiveCount(0);
    seen.current = new Set(initial.map((x) => x.id));
  }, [data]);

  useInteractionStream(
    qs,
    useCallback((i: InteractionSummary) => {
      if (seen.current.has(i.id)) return;
      seen.current.add(i.id);
      setItems((prev) => [i, ...prev].slice(0, 200));
      setLiveCount((c) => c + 1);
    }, []),
  );

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        {FILTERS.map(({ key, label }) => (
          <div key={key} className="space-y-1">
            <label className="text-xs text-muted-foreground">{label}</label>
            <Input
              className="h-8 w-full sm:w-48"
              placeholder={label}
              defaultValue={params.get(key) ?? ""}
              onBlur={(e) => setFilter(key, e.target.value.trim())}
              onKeyDown={(e) => {
                if (e.key === "Enter")
                  setFilter(key, (e.target as HTMLInputElement).value.trim());
              }}
            />
          </div>
        ))}
        {qs && (
          <Button variant="ghost" size="sm" onClick={() => setParams({})}>
            Clear
          </Button>
        )}
        <span
          className="ml-auto flex items-center gap-1.5 text-xs text-muted-foreground"
          title="Live updates via server-sent events"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          Live
        </span>
      </div>

      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Method</TableHead>
            <TableHead>Path</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Handler</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && (
            <TableRow>
              <TableCell colSpan={5} className="text-muted-foreground">
                Loading…
              </TableCell>
            </TableRow>
          )}
          {!loading && items.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-muted-foreground">
                No events.
              </TableCell>
            </TableRow>
          )}
          {items.map((i) => (
            <TableRow key={i.id}>
              <TableCell className="whitespace-nowrap text-muted-foreground">
                {new Date(i.created_at).toLocaleString()}
              </TableCell>
              <TableCell>{i.request_type}</TableCell>
              <TableCell className="font-mono">
                <Link className="hover:underline" to={`/events/${i.id}`}>
                  {i.request_target || "/"}
                </Link>
              </TableCell>
              <TableCell className="font-mono">{i.remote_addr}</TableCell>
              <TableCell>{i.handler}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {data && (
        <p className="text-xs text-muted-foreground">
          {data.total + liveCount} total{qs ? " (filtered)" : ""}
          {liveCount > 0 && ` · ${liveCount} new`}
        </p>
      )}
    </div>
  );
}

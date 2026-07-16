import { useCallback, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useInteractionStream } from "@/lib/useStream";
import { useLiveFeed } from "@/lib/useLiveFeed";
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
import { LiveIndicator } from "@/components/LiveIndicator";

const FILTERS = [
  { key: "target", label: "Target" },
  { key: "remote", label: "Source IP" },
  { key: "handler", label: "Handler" },
] as const;

export default function Events() {
  const [params, setParams] = useSearchParams();
  const [formError, setFormError] = useState<string | null>(null);

  const query = new URLSearchParams();
  for (const { key } of FILTERS) {
    const v = params.get(key);
    if (v) query.set(key, v);
  }
  const qs = query.toString();
  const { data, error, loading, reload } = useApi<InteractionPage>(
    "interactions" + (qs ? "?" + qs : ""),
  );

  // Seed from the fetched page, then prepend live events. The server applies
  // the same filters to the stream, so anything received belongs in this view.
  const { items, liveCount, claim, add } = useLiveFeed<InteractionSummary>(
    data?.items,
  );
  useInteractionStream(
    qs,
    useCallback(
      (i: InteractionSummary) => {
        if (claim(i.id)) add(i);
      },
      [claim, add],
    ),
  );

  async function onDeleteEvent(id: number) {
    if (!window.confirm("Delete this event and its files?")) return;
    try {
      await api.del(`interactions/${id}`);
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

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
        <span className="ml-auto">
          <LiveIndicator />
        </span>
      </div>

      {(error || formError) && (
        <p className="text-sm text-destructive" role="alert">
          {formError ?? error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Handler</TableHead>
            <TableHead></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && (
            <TableRow>
              <TableCell colSpan={6} className="text-muted-foreground">
                Loading…
              </TableCell>
            </TableRow>
          )}
          {!loading && items.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} className="text-muted-foreground">
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
              <TableCell className="text-right">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onDeleteEvent(i.id)}
                >
                  Delete
                </Button>
              </TableCell>
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

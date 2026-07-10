import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import { useInteractionStream } from "@/lib/useStream";
import type {
  InteractionSummary,
  SinkDetail as SinkDetailData,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function SinkDetail() {
  const { slug = "" } = useParams();
  const { data, error, loading } = useApi<SinkDetailData>(
    `sinks/${encodeURIComponent(slug)}`,
  );

  // Hooks must run unconditionally (before the early returns below).
  const [events, setEvents] = useState<InteractionSummary[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  useEffect(() => {
    setEvents(data?.events ?? []);
    setLiveCount(0);
  }, [data]);

  useInteractionStream(
    `sink=${encodeURIComponent(slug)}`,
    useCallback((i: InteractionSummary) => {
      setEvents((prev) =>
        prev.some((x) => x.id === i.id) ? prev : [i, ...prev].slice(0, 200),
      );
      setLiveCount((c) => c + 1);
    }, []),
  );

  if (loading) return <p className="text-muted-foreground">Loading…</p>;
  if (error)
    return (
      <p className="text-sm text-destructive" role="alert">
        {error}
      </p>
    );
  if (!data) return null;

  const total = data.total + liveCount;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/sinks"
          className="text-sm text-muted-foreground hover:underline"
        >
          ← Sinks
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-lg">{data.slug}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            {data.description || (
              <span className="text-muted-foreground">No description.</span>
            )}
          </p>
          <div className="flex items-center gap-3">
            <code className="rounded bg-muted p-2 text-xs">{data.slug}</code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigator.clipboard?.writeText(data.slug)}
            >
              Copy slug
            </Button>
          </div>
          <p className="text-muted-foreground">
            {total} event{total === 1 ? "" : "s"} · created{" "}
            {new Date(data.created_at).toLocaleString()}
          </p>
        </CardContent>
      </Card>

      <div>
        <div className="mb-2 flex items-center gap-2">
          <h2 className="text-sm font-medium">Events (most recent first)</h2>
          <span
            className="flex items-center gap-1.5 text-xs text-muted-foreground"
            title="Live updates via server-sent events"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            Live
          </span>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Handler</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Source</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground">
                  No events for this sink yet.
                </TableCell>
              </TableRow>
            )}
            {events.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="whitespace-nowrap text-muted-foreground">
                  {new Date(e.created_at).toLocaleString()}
                </TableCell>
                <TableCell>{e.handler}</TableCell>
                <TableCell>{e.request_type}</TableCell>
                <TableCell className="font-mono">
                  <Link className="hover:underline" to={`/requests/${e.id}`}>
                    {e.request_target || "/"}
                  </Link>
                </TableCell>
                <TableCell className="font-mono">{e.remote_addr}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

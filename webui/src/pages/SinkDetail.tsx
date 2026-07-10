import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useInteractionStream } from "@/lib/useStream";
import type {
  InteractionSummary,
  Sink,
  SinkDetail as SinkDetailData,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
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
  const [description, setDescription] = useState("");
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  useEffect(() => {
    setEvents(data?.events ?? []);
    setLiveCount(0);
    setDescription(data?.description ?? "");
    setEditing(false);
  }, [data]);

  async function saveDescription() {
    setSaving(true);
    setSaveError(null);
    try {
      const updated = await api.put<Sink>(`sinks/${encodeURIComponent(slug)}`, {
        description: draft,
      });
      setDescription(updated.description);
      setEditing(false);
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "save failed");
    } finally {
      setSaving(false);
    }
  }

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
          {editing ? (
            <div className="space-y-2">
              <Textarea
                aria-label="Sink description"
                rows={3}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="What is this sink for?"
              />
              {saveError && (
                <p className="text-sm text-destructive" role="alert">
                  {saveError}
                </p>
              )}
              <div className="flex gap-2">
                <Button size="sm" onClick={saveDescription} disabled={saving}>
                  {saving ? "Saving…" : "Save"}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditing(false)}
                  disabled={saving}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex items-start justify-between gap-3">
              <p>
                {description || (
                  <span className="text-muted-foreground">No description.</span>
                )}
              </p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setDraft(description);
                  setSaveError(null);
                  setEditing(true);
                }}
              >
                Edit
              </Button>
            </div>
          )}
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

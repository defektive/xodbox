import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { sinkLink } from "@/lib/base";
import { useApi } from "@/lib/useApi";
import { useInteractionStream } from "@/lib/useStream";
import { useLiveFeed } from "@/lib/useLiveFeed";
import { useCopy } from "@/lib/useCopy";
import type {
  InteractionDetail,
  InteractionSummary,
  Sink,
  SinkDetail as SinkDetailData,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { InteractionDetailView } from "@/components/InteractionDetail";
import { LiveIndicator } from "@/components/LiveIndicator";

export default function SinkDetail() {
  const { slug = "" } = useParams();
  const { data, error, loading } = useApi<SinkDetailData>(
    `sinks/${encodeURIComponent(slug)}`,
  );

  // Hooks must run unconditionally (before the early returns below).
  const {
    items: events,
    liveCount,
    claim,
    add,
    release,
  } = useLiveFeed<InteractionDetail>(data?.events);
  const [description, setDescription] = useState("");
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const slugCopy = useCopy();
  const linkCopy = useCopy();
  useEffect(() => {
    setDescription(data?.description ?? "");
    setEditing(false);
  }, [data]);

  // The stream carries summaries; fetch the full detail for each new hit so the
  // timeline can render it inline.
  useInteractionStream(
    `sink=${encodeURIComponent(slug)}`,
    useCallback(
      (s: InteractionSummary) => {
        if (!claim(s.id)) return;
        api
          .get<InteractionDetail>(`interactions/${s.id}`)
          .then(add)
          .catch(() => release(s.id)); // transient; allow a later retry
      },
      [claim, add, release],
    ),
  );

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
          <div className="flex flex-wrap items-center gap-3">
            <code className="rounded bg-muted p-2 text-xs">{data.slug}</code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => slugCopy.copy(data.slug)}
            >
              {slugCopy.copied ? "Copied!" : "Copy slug"}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => linkCopy.copy(sinkLink(data.slug))}
              title={sinkLink(data.slug)}
            >
              {linkCopy.copied ? "Copied!" : "Copy HTTP link"}
            </Button>
          </div>
          <p className="text-muted-foreground">
            {total} event{total === 1 ? "" : "s"} · created{" "}
            {new Date(data.created_at).toLocaleString()}
          </p>
        </CardContent>
      </Card>

      <div>
        <div className="mb-3 flex items-center gap-2">
          <h2 className="text-sm font-medium">Event timeline</h2>
          <LiveIndicator />
        </div>

        {events.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No events for this sink yet.
          </p>
        ) : (
          <ol className="space-y-4 border-l pl-5">
            {events.map((e) => (
              <li key={e.id} className="relative">
                <span className="absolute -left-[27px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-emerald-500" />
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="font-mono text-sm">
                    {e.request_type} {e.request_target || "/"}
                  </span>
                  <Link
                    className="text-xs text-muted-foreground hover:underline"
                    to={`/events/${e.id}`}
                  >
                    open ↗
                  </Link>
                </div>
                <Card className="mt-2">
                  <CardContent className="pt-4">
                    <InteractionDetailView d={e} />
                  </CardContent>
                </Card>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}

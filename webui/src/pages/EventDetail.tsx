import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { InteractionDetail } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { InteractionDetailView } from "@/components/InteractionDetail";

export default function EventDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data, error, loading, reload } = useApi<InteractionDetail>(
    `interactions/${id}`,
  );
  const [deleteError, setDeleteError] = useState<string | null>(null);

  async function onDelete() {
    if (!window.confirm("Delete this event and its files?")) return;
    try {
      await api.del(`interactions/${id}`);
      navigate("/events");
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  async function onDeleteFile(fileId: number) {
    if (!window.confirm("Delete this file?")) return;
    try {
      await api.del(`interactions/${id}/files/${fileId}`);
      reload();
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }
  if (error || !data) {
    return (
      <p className="text-sm text-destructive" role="alert">
        {error ?? "not found"}
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Link
          to="/events"
          className="text-sm text-muted-foreground hover:underline"
        >
          ← Back to events
        </Link>
        <Button variant="destructive" size="sm" onClick={onDelete}>
          Delete event
        </Button>
      </div>

      {deleteError && (
        <p className="text-sm text-destructive" role="alert">
          {deleteError}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-base">
            {data.request_type} {data.request_target}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <InteractionDetailView d={data} onDeleteFile={onDeleteFile} />
        </CardContent>
      </Card>
    </div>
  );
}

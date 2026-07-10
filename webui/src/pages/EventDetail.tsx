import { Link, useParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { InteractionDetail } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { InteractionDetailView } from "@/components/InteractionDetail";

export default function EventDetail() {
  const { id } = useParams();
  const { data, error, loading } = useApi<InteractionDetail>(
    `interactions/${id}`,
  );

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
      <Link
        to="/events"
        className="text-sm text-muted-foreground hover:underline"
      >
        ← Back to events
      </Link>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-base">
            {data.request_type} {data.request_target}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <InteractionDetailView d={data} />
        </CardContent>
      </Card>
    </div>
  );
}

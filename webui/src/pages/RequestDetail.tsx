import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { InteractionDetail } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function CopyCurl({ curl }: { curl: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }
  return (
    <Button size="sm" variant="outline" onClick={copy}>
      {copied ? "Copied!" : "Copy as curl"}
    </Button>
  );
}

export default function RequestDetail() {
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
      <Link to="/requests" className="text-sm text-muted-foreground hover:underline">
        ← Back to requests
      </Link>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="font-mono text-base">
            {data.request_type} {data.request_target}
          </CardTitle>
          {data.curl && <CopyCurl curl={data.curl} />}
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
          <Meta label="Source" value={`${data.remote_addr}:${data.remote_port}`} />
          <Meta label="Protocol" value={data.protocol} />
          <Meta label="Handler" value={data.handler} />
          <Meta label="Time" value={new Date(data.created_at).toLocaleString()} />
        </CardContent>
      </Card>

      {data.curl && (
        <Section title="Replay">
          <pre className="overflow-auto rounded-md bg-muted p-3 text-xs">
            {data.curl}
          </pre>
        </Section>
      )}

      <Section title="Raw request">
        <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
          {data.headers}
        </pre>
      </Section>

      {data.body && (
        <Section title="Body">
          <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
            {data.body}
          </pre>
        </Section>
      )}
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono">{value}</div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

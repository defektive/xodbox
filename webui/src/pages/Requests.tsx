import { Link, useSearchParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { InteractionPage } from "@/lib/types";
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

export default function Requests() {
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
              className="h-8 w-48"
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
          {!loading && data?.items.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-muted-foreground">
                No requests.
              </TableCell>
            </TableRow>
          )}
          {data?.items.map((i) => (
            <TableRow key={i.id}>
              <TableCell className="whitespace-nowrap text-muted-foreground">
                {new Date(i.created_at).toLocaleString()}
              </TableCell>
              <TableCell>{i.request_type}</TableCell>
              <TableCell className="font-mono">
                <Link className="hover:underline" to={`/requests/${i.id}`}>
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
          {data.total} total{qs ? " (filtered)" : ""}
        </p>
      )}
    </div>
  );
}

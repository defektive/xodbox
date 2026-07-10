import { Link, useNavigate } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { Payload } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function Payloads() {
  const navigate = useNavigate();
  const { data, error, loading } = useApi<Payload[]>("payloads");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          HTTP response payloads, matched by pattern in priority order.
        </p>
        <Button size="sm" onClick={() => navigate("/payloads/new")}>
          New payload
        </Button>
      </div>

      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Order</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Pattern</TableHead>
            <TableHead>Final</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && (
            <TableRow>
              <TableCell colSpan={4} className="text-muted-foreground">
                Loading…
              </TableCell>
            </TableRow>
          )}
          {!loading && data?.length === 0 && (
            <TableRow>
              <TableCell colSpan={4} className="text-muted-foreground">
                No payloads.
              </TableCell>
            </TableRow>
          )}
          {data?.map((p) => (
            <TableRow key={p.id}>
              <TableCell>{p.sort_order}</TableCell>
              <TableCell>
                <Link className="hover:underline" to={`/payloads/${p.id}`}>
                  {p.name}
                </Link>
              </TableCell>
              <TableCell className="font-mono">{p.pattern}</TableCell>
              <TableCell>{p.is_final ? "yes" : "no"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

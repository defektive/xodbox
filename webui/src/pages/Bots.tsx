import { Link } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { Bot } from "@/lib/types";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function Bots() {
  const { data, error, loading } = useApi<Bot[]>("bots");

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Sources exceeding 30 requests in a one-minute window.
      </p>
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Source IP</TableHead>
            <TableHead>Requests / min</TableHead>
            <TableHead></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && (
            <TableRow>
              <TableCell colSpan={3} className="text-muted-foreground">
                Loading…
              </TableCell>
            </TableRow>
          )}
          {!loading && data?.length === 0 && (
            <TableRow>
              <TableCell colSpan={3} className="text-muted-foreground">
                No bots detected.
              </TableCell>
            </TableRow>
          )}
          {data?.map((b, idx) => (
            <TableRow key={`${b.remote_addr}-${idx}`}>
              <TableCell className="font-mono">{b.remote_addr}</TableCell>
              <TableCell>{b.total}</TableCell>
              <TableCell>
                <Link
                  className="text-sm hover:underline"
                  to={`/requests?remote=${encodeURIComponent(b.remote_addr)}`}
                >
                  view requests
                </Link>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

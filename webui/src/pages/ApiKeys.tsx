import { useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { ApiKey } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function ApiKeys() {
  const { data, error, loading, reload } = useApi<ApiKey[]>("apikeys");
  const [name, setName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      const created = await api.post<ApiKey & { key: string }>("apikeys", {
        name,
      });
      setNewKey(created.key);
      setName("");
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "create failed");
    }
  }

  async function onDelete(id: number) {
    if (!window.confirm("Revoke this key?")) return;
    try {
      await api.del(`apikeys/${id}`);
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={onCreate} className="flex items-end gap-3">
        <div className="space-y-1">
          <label className="text-sm font-medium" htmlFor="k-name">
            Key name
          </label>
          <Input
            id="k-name"
            className="w-64"
            placeholder="e.g. ci-runner"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <Button type="submit">Create key</Button>
      </form>

      {newKey && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              Copy your new key — it won't be shown again
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-3">
            <code className="flex-1 break-all rounded bg-muted p-2 text-xs">
              {newKey}
            </code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigator.clipboard?.writeText(newKey)}
            >
              Copy
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setNewKey(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      {(formError || error) && (
        <p className="text-sm text-destructive" role="alert">
          {formError ?? error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Prefix</TableHead>
            <TableHead>Last used</TableHead>
            <TableHead></TableHead>
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
                No keys.
              </TableCell>
            </TableRow>
          )}
          {data?.map((k) => (
            <TableRow key={k.id}>
              <TableCell>{k.name}</TableCell>
              <TableCell className="font-mono">{k.prefix}…</TableCell>
              <TableCell className="text-muted-foreground">
                {k.last_used_at
                  ? new Date(k.last_used_at).toLocaleString()
                  : "never"}
              </TableCell>
              <TableCell className="text-right">
                <Button variant="ghost" size="sm" onClick={() => onDelete(k.id)}>
                  Revoke
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

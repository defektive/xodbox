import { useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { UserRow } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function Users({ currentUserId }: { currentUserId: number }) {
  const { data, error, loading, reload } = useApi<UserRow[]>("users");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [formError, setFormError] = useState<string | null>(null);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      await api.post("users", { username, password, role });
      setUsername("");
      setPassword("");
      setRole("user");
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "create failed");
    }
  }

  async function onDelete(id: number) {
    if (!window.confirm("Delete this user?")) return;
    try {
      await api.del(`users/${id}`);
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={onCreate} className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label htmlFor="u-name">Username</Label>
          <Input
            id="u-name"
            className="w-48"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="u-pass">Password</Label>
          <Input
            id="u-pass"
            className="w-56"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="u-role">Role</Label>
          <select
            id="u-role"
            className="h-9 rounded-md border border-input bg-transparent px-2 text-sm"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <Button type="submit">Add user</Button>
      </form>

      {(formError || error) && (
        <p className="text-sm text-destructive" role="alert">
          {formError ?? error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Username</TableHead>
            <TableHead>Role</TableHead>
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
          {data?.map((u) => (
            <TableRow key={u.id}>
              <TableCell>{u.username}</TableCell>
              <TableCell>{u.role}</TableCell>
              <TableCell className="text-right">
                {u.id !== currentUserId && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onDelete(u.id)}
                  >
                    Delete
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

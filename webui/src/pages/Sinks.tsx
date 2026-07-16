import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { Sink } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function Sinks() {
  const { data, error, loading, reload } = useApi<Sink[]>("sinks");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [notify, setNotify] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      // slug is optional — the server generates one when it's blank.
      await api.post<Sink>("sinks", { slug: slug.trim(), description, notify });
      setSlug("");
      setDescription("");
      setNotify(false);
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "create failed");
    }
  }

  async function onToggleNotify(s: Sink) {
    try {
      await api.put<Sink>(`sinks/${encodeURIComponent(s.slug)}`, {
        notify: !s.notify,
      });
      reload();
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "toggle notify failed",
      );
    }
  }

  async function onDelete(s: string) {
    if (!window.confirm(`Delete sink "${s}"? Its captured events are kept.`))
      return;
    try {
      await api.del(`sinks/${encodeURIComponent(s)}`);
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Sinks are named, described slugs you embed in payloads to correlate
        out-of-band interactions. Leave the slug blank to generate one.
      </p>

      <form onSubmit={onCreate} className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <label className="text-sm font-medium" htmlFor="s-slug">
            Slug (optional)
          </label>
          <Input
            id="s-slug"
            className="w-48 font-mono"
            placeholder="auto-generate"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium" htmlFor="s-desc">
            Description
          </label>
          <Input
            id="s-desc"
            className="w-80"
            placeholder="what is this sink for?"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <div className="flex items-end gap-2">
          <label className="flex items-center gap-1.5 text-sm">
            <input
              type="checkbox"
              checked={notify}
              onChange={(e) => setNotify(e.target.checked)}
              className="accent-emerald-500"
            />
            Notify
          </label>
        </div>
        <Button type="submit">Create sink</Button>
      </form>

      {(formError || error) && (
        <p className="text-sm text-destructive" role="alert">
          {formError ?? error}
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Slug</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Hits</TableHead>
            <TableHead>Notify</TableHead>
            <TableHead></TableHead>
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
          {!loading && data?.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-muted-foreground">
                No sinks yet.
              </TableCell>
            </TableRow>
          )}
          {data?.map((s) => (
            <TableRow key={s.slug}>
              <TableCell className="font-mono">
                <Link
                  className="hover:underline"
                  to={`/sinks/${encodeURIComponent(s.slug)}`}
                >
                  {s.slug}
                </Link>
              </TableCell>
              <TableCell>{s.description}</TableCell>
              <TableCell>{s.event_count}</TableCell>
              <TableCell>
                <button
                  type="button"
                  onClick={() => onToggleNotify(s)}
                  className={`inline-block h-4 w-4 rounded-sm border ${s.notify ? "border-emerald-500 bg-emerald-500" : "border-muted-foreground"}`}
                  title={s.notify ? "Notifications on" : "Notifications off"}
                  aria-label={`Toggle notifications for ${s.slug}`}
                />
              </TableCell>
              <TableCell className="text-right">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onDelete(s.slug)}
                >
                  Delete
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

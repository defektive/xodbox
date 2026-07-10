import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import type { Payload } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface FormState {
  name: string;
  description: string;
  pattern: string;
  status_code: string;
  sort_order: string;
  is_final: boolean;
  body: string;
  headersJson: string;
}

const EMPTY: FormState = {
  name: "",
  description: "",
  pattern: "",
  status_code: "",
  sort_order: "0",
  is_final: false,
  body: "",
  headersJson: "{}",
};

function validatePattern(p: string): string | null {
  if (!p) return null;
  try {
    new RegExp(p);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

function validateHeaders(s: string): string | null {
  if (!s.trim()) return null;
  try {
    const v = JSON.parse(s);
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      return "headers must be a JSON object";
    }
    return null;
  } catch {
    return "invalid JSON";
  }
}

export default function PayloadEditor() {
  const { id } = useParams();
  const navigate = useNavigate();
  const isNew = !id || id === "new";

  const [form, setForm] = useState<FormState>(EMPTY);
  const [loading, setLoading] = useState(!isNew);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isNew) return;
    let active = true;
    api
      .get<Payload>(`payloads/${id}`)
      .then((p) => {
        if (!active) return;
        setForm({
          name: p.name,
          description: p.description,
          pattern: p.pattern,
          status_code: p.status_code,
          sort_order: String(p.sort_order),
          is_final: p.is_final,
          body: p.body,
          headersJson: JSON.stringify(p.headers ?? {}, null, 2),
        });
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "load failed"))
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [id, isNew]);

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  const patternError = validatePattern(form.pattern);
  const headersError = validateHeaders(form.headersJson);
  const invalid = !!patternError || !!headersError || !form.name.trim();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (invalid) return;
    setSaving(true);
    setError(null);
    const body = {
      name: form.name,
      description: form.description,
      pattern: form.pattern,
      status_code: form.status_code,
      sort_order: Number(form.sort_order) || 0,
      is_final: form.is_final,
      body: form.body,
      headers: JSON.parse(form.headersJson || "{}"),
    };
    try {
      if (isNew) await api.post("payloads", body);
      else await api.put(`payloads/${id}`, body);
      navigate("/payloads");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "save failed");
      setSaving(false);
    }
  }

  async function onDelete() {
    if (isNew || !window.confirm("Delete this payload?")) return;
    try {
      await api.del(`payloads/${id}`);
      navigate("/payloads");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "delete failed");
    }
  }

  if (loading) return <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <Card className="max-w-3xl">
      <CardHeader>
        <CardTitle>{isNew ? "New payload" : "Edit payload"}</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-4">
          <Field label="Name" htmlFor="pl-name">
            <Input
              id="pl-name"
              value={form.name}
              onChange={(e) => set("name", e.target.value)}
            />
          </Field>
          <Field label="Description" htmlFor="pl-desc">
            <Input
              id="pl-desc"
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
            />
          </Field>
          <Field label="Pattern (regex)" htmlFor="pl-pattern" error={patternError}>
            <Input
              id="pl-pattern"
              className="font-mono"
              value={form.pattern}
              onChange={(e) => set("pattern", e.target.value)}
            />
          </Field>
          <div className="flex flex-wrap gap-4">
            <Field label="Status code" className="w-32">
              <Input
                value={form.status_code}
                placeholder="200"
                onChange={(e) => set("status_code", e.target.value)}
              />
            </Field>
            <Field label="Sort order" className="w-32">
              <Input
                type="number"
                value={form.sort_order}
                onChange={(e) => set("sort_order", e.target.value)}
              />
            </Field>
            <label className="flex items-center gap-2 self-end pb-2 text-sm">
              <input
                type="checkbox"
                checked={form.is_final}
                onChange={(e) => set("is_final", e.target.checked)}
              />
              Final (stop matching)
            </label>
          </div>
          <Field label="Response body">
            <Textarea
              className="min-h-[140px]"
              value={form.body}
              onChange={(e) => set("body", e.target.value)}
            />
          </Field>
          <Field label="Response headers (JSON)" error={headersError}>
            <Textarea
              value={form.headersJson}
              onChange={(e) => set("headersJson", e.target.value)}
            />
          </Field>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <div className="flex items-center gap-2">
            <Button type="submit" disabled={invalid || saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => navigate("/payloads")}
            >
              Cancel
            </Button>
            {!isNew && (
              <Button
                type="button"
                variant="destructive"
                className="ml-auto"
                onClick={onDelete}
              >
                Delete
              </Button>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Field({
  label,
  htmlFor,
  error,
  className,
  children,
}: {
  label: string;
  htmlFor?: string;
  error?: string | null;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={className ? className + " space-y-1" : "space-y-1"}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

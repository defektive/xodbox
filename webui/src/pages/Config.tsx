import { useState, useEffect, type FormEvent } from "react";
import { dump as yamlDump, load as yamlLoad } from "js-yaml";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface ConfigData {
  configPath: string;
  defaults: Record<string, string> | null;
  handlers: Record<string, string>[] | null;
  notifiers: Record<string, string>[] | null;
  workers: Record<string, string>[] | null;
}

interface ConfigSchema {
  handlers: string[];
  notifiers: string[];
  workers: string[];
}

type Tab = "editor" | "yaml";

export default function Config() {
  const { data, error, loading, reload } = useApi<ConfigData>("config");
  const { data: schema } = useApi<ConfigSchema>("config/schema");

  const [tab, setTab] = useState<Tab>("editor");
  const [defaults, setDefaults] = useState<[string, string][]>([]);
  const [handlers, setHandlers] = useState<Record<string, string>[]>([]);
  const [notifiers, setNotifiers] = useState<Record<string, string>[]>([]);
  const [workers, setWorkers] = useState<Record<string, string>[]>([]);
  const [yamlText, setYamlText] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!data) return;
    setDefaults(Object.entries(data.defaults ?? {}));
    setHandlers((data.handlers ?? []).map((h) => ({ ...h })));
    setNotifiers((data.notifiers ?? []).map((n) => ({ ...n })));
    setWorkers((data.workers ?? []).map((w) => ({ ...w })));
    setYamlText(
      yamlDump({
        defaults: data.defaults,
        handlers: data.handlers,
        notifiers: data.notifiers,
        workers: data.workers,
      }),
    );
  }, [data]);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSaveError(null);
    setSaved(false);

    let body: {
      defaults: Record<string, string>;
      handlers: Record<string, string>[];
      notifiers: Record<string, string>[];
      workers: Record<string, string>[];
    };

    if (tab === "yaml") {
      try {
        const parsed = yamlLoad(yamlText) as ConfigData;
        body = {
          defaults: parsed?.defaults ?? {},
          handlers: parsed?.handlers ?? [],
          notifiers: parsed?.notifiers ?? [],
          workers: parsed?.workers ?? [],
        };
      } catch (err) {
        setSaveError(
          "Invalid YAML: " +
            (err instanceof Error ? err.message : String(err)),
        );
        setSaving(false);
        return;
      }
    } else {
      body = {
        defaults: Object.fromEntries(defaults.filter(([k]) => k.trim())),
        handlers,
        notifiers,
        workers,
      };
    }

    try {
      const res = await api.put<{ saved: boolean; reloading: boolean }>(
        "config",
        body,
      );
      setSaved(true);
      if (res?.reloading) {
        setTimeout(() => {
          reload();
        }, 3000);
      } else {
        reload();
      }
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "save failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <p className="text-muted-foreground">Loading config…</p>;
  }
  if (error) {
    return (
      <p className="text-destructive" role="alert">
        {error}
      </p>
    );
  }

  return (
    <form onSubmit={onSave} className="space-y-6">
      {saved && (
        <div className="rounded-md border border-green-600/30 bg-green-600/10 px-4 py-3 text-sm text-green-700 dark:text-green-400">
          Config saved. Reloading handlers…
        </div>
      )}
      {saveError && (
        <p className="text-sm text-destructive" role="alert">
          {saveError}
        </p>
      )}

      {data?.configPath && (
        <p className="text-xs text-muted-foreground">
          Config file: {data.configPath}
        </p>
      )}

      <div className="flex gap-2">
        <Button
          type="button"
          variant={tab === "editor" ? "default" : "outline"}
          size="sm"
          onClick={() => setTab("editor")}
        >
          Editor
        </Button>
        <Button
          type="button"
          variant={tab === "yaml" ? "default" : "outline"}
          size="sm"
          onClick={() => setTab("yaml")}
        >
          YAML
        </Button>
      </div>

      {tab === "editor" ? (
        <div className="space-y-6">
          <DefaultsSection defaults={defaults} onChange={setDefaults} />
          <MapSliceSection
            title="Handlers"
            typeKey="handler"
            typeOptions={schema?.handlers ?? []}
            items={handlers}
            onChange={setHandlers}
          />
          <MapSliceSection
            title="Notifiers"
            typeKey="notifier"
            typeOptions={schema?.notifiers ?? []}
            items={notifiers}
            onChange={setNotifiers}
          />
          <MapSliceSection
            title="Workers"
            typeKey="worker"
            typeOptions={schema?.workers ?? []}
            items={workers}
            onChange={setWorkers}
          />
        </div>
      ) : (
        <div className="space-y-2">
          <Label htmlFor="yaml-editor">Raw YAML</Label>
          <Textarea
            id="yaml-editor"
            className="min-h-[400px] font-mono text-sm"
            value={yamlText}
            onChange={(e) => setYamlText(e.target.value)}
          />
        </div>
      )}

      <Button type="submit" disabled={saving}>
        {saving ? "Saving…" : "Save config"}
      </Button>
    </form>
  );
}

function DefaultsSection({
  defaults,
  onChange,
}: {
  defaults: [string, string][];
  onChange: (v: [string, string][]) => void;
}) {
  function update(i: number, ki: 0 | 1, val: string) {
    const next = [...defaults];
    next[i] = [...next[i]] as [string, string];
    next[i][ki] = val;
    onChange(next);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Defaults</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {defaults.map(([k, v], i) => (
          <div key={i} className="flex items-end gap-2">
            <div className="space-y-1 flex-1">
              {i === 0 && <Label>Key</Label>}
              <Input
                value={k}
                onChange={(e) => update(i, 0, e.target.value)}
                placeholder="key"
              />
            </div>
            <div className="space-y-1 flex-1">
              {i === 0 && <Label>Value</Label>}
              <Input
                value={v}
                onChange={(e) => update(i, 1, e.target.value)}
                placeholder="value"
              />
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => onChange(defaults.filter((_, j) => j !== i))}
            >
              Remove
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange([...defaults, ["", ""]])}
        >
          Add default
        </Button>
      </CardContent>
    </Card>
  );
}

function MapSliceSection({
  title,
  typeKey,
  typeOptions,
  items,
  onChange,
}: {
  title: string;
  typeKey: string;
  typeOptions: string[];
  items: Record<string, string>[];
  onChange: (v: Record<string, string>[]) => void;
}) {
  function updateItem(index: number, updated: Record<string, string>) {
    const next = [...items];
    next[index] = updated;
    onChange(next);
  }

  function removeItem(index: number) {
    onChange(items.filter((_, i) => i !== index));
  }

  function addItem() {
    onChange([...items, { [typeKey]: typeOptions[0] ?? "" }]);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {items.map((item, i) => (
          <MapEntryCard
            key={i}
            typeKey={typeKey}
            typeOptions={typeOptions}
            item={item}
            onUpdate={(updated) => updateItem(i, updated)}
            onRemove={() => removeItem(i)}
          />
        ))}
        <Button type="button" variant="outline" size="sm" onClick={addItem}>
          Add {typeKey}
        </Button>
      </CardContent>
    </Card>
  );
}

function MapEntryCard({
  typeKey,
  typeOptions,
  item,
  onUpdate,
  onRemove,
}: {
  typeKey: string;
  typeOptions: string[];
  item: Record<string, string>;
  onUpdate: (updated: Record<string, string>) => void;
  onRemove: () => void;
}) {
  const extraKeys = Object.keys(item).filter((k) => k !== typeKey);

  function setField(key: string, val: string) {
    onUpdate({ ...item, [key]: val });
  }

  function removeField(key: string) {
    const next = { ...item };
    delete next[key];
    onUpdate(next);
  }

  function addField() {
    onUpdate({ ...item, "": "" });
  }

  return (
    <div className="rounded-md border p-3 space-y-2">
      <div className="flex items-center gap-2">
        <Label className="w-20 shrink-0">{typeKey}</Label>
        <select
          className="h-9 flex-1 rounded-md border border-input bg-transparent px-2 text-sm"
          value={item[typeKey] ?? ""}
          onChange={(e) => setField(typeKey, e.target.value)}
        >
          {typeOptions.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <Button type="button" variant="ghost" size="sm" onClick={onRemove}>
          Remove
        </Button>
      </div>
      {extraKeys.map((key) => (
        <div key={key} className="flex items-end gap-2 pl-4">
          <Input
            className="w-40"
            value={key}
            onChange={(e) => {
              const next = { ...item };
              const val = next[key];
              delete next[key];
              next[e.target.value] = val;
              onUpdate(next);
            }}
            placeholder="key"
          />
          <Input
            className="flex-1"
            value={item[key]}
            onChange={(e) => setField(key, e.target.value)}
            placeholder="value"
          />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => removeField(key)}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="ml-4"
        onClick={addField}
      >
        Add field
      </Button>
    </div>
  );
}

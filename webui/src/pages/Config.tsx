import { useState, useEffect, type FormEvent } from "react";
import { dump as yamlDump, load as yamlLoad } from "js-yaml";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface FieldMeta {
  key: string;
  label: string;
  description?: string;
  required?: boolean;
  default?: string;
  group?: string;
  sensitive?: boolean;
}

interface TypeMeta {
  fields: FieldMeta[];
}

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
  fields?: Record<string, TypeMeta>;
  defaultFields?: FieldMeta[];
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
          <DefaultsSection
            defaults={defaults}
            onChange={setDefaults}
            fieldMeta={schema?.defaultFields}
          />
          <MapSliceSection
            title="Handlers"
            typeKey="handler"
            typeOptions={schema?.handlers ?? []}
            items={handlers}
            onChange={setHandlers}
            fieldSchema={schema?.fields}
          />
          <MapSliceSection
            title="Notifiers"
            typeKey="notifier"
            typeOptions={schema?.notifiers ?? []}
            items={notifiers}
            onChange={setNotifiers}
            fieldSchema={schema?.fields}
          />
          <MapSliceSection
            title="Workers"
            typeKey="worker"
            typeOptions={schema?.workers ?? []}
            items={workers}
            onChange={setWorkers}
            fieldSchema={schema?.fields}
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
  fieldMeta,
}: {
  defaults: [string, string][];
  onChange: (v: [string, string][]) => void;
  fieldMeta?: FieldMeta[];
}) {
  function update(i: number, ki: 0 | 1, val: string) {
    const next = [...defaults];
    next[i] = [...next[i]] as [string, string];
    next[i][ki] = val;
    onChange(next);
  }

  const presentKeys = new Set(defaults.map(([k]) => k));
  const missingKnown = (fieldMeta ?? []).filter(
    (f) => !presentKeys.has(f.key),
  );

  function addKnownField(field: FieldMeta) {
    onChange([...defaults, [field.key, field.default ?? ""]]);
  }

  function getMeta(key: string): FieldMeta | undefined {
    return fieldMeta?.find((f) => f.key === key);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Defaults</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {defaults.map(([k, v], i) => {
          const meta = getMeta(k);
          return (
            <div key={i} className="flex items-start gap-2">
              <div className="space-y-1 flex-1">
                {meta ? (
                  <>
                    <Label className="text-sm font-medium">{meta.label}</Label>
                    {meta.description && (
                      <p className="text-xs text-muted-foreground">
                        {meta.description}
                      </p>
                    )}
                    <Input
                      value={v}
                      onChange={(e) => update(i, 1, e.target.value)}
                      placeholder={meta.default ?? ""}
                    />
                  </>
                ) : (
                  <div className="flex gap-2">
                    <Input
                      className="w-40"
                      value={k}
                      onChange={(e) => update(i, 0, e.target.value)}
                      placeholder="key"
                    />
                    <Input
                      className="flex-1"
                      value={v}
                      onChange={(e) => update(i, 1, e.target.value)}
                      placeholder="value"
                    />
                  </div>
                )}
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="mt-1 shrink-0"
                onClick={() => onChange(defaults.filter((_, j) => j !== i))}
              >
                Remove
              </Button>
            </div>
          );
        })}
        <div className="flex flex-wrap gap-2">
          {missingKnown.map((field) => (
            <Button
              key={field.key}
              type="button"
              variant="outline"
              size="sm"
              onClick={() => addKnownField(field)}
            >
              + {field.label}
            </Button>
          ))}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onChange([...defaults, ["", ""]])}
          >
            + Custom field
          </Button>
        </div>
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
  fieldSchema,
}: {
  title: string;
  typeKey: string;
  typeOptions: string[];
  items: Record<string, string>[];
  onChange: (v: Record<string, string>[]) => void;
  fieldSchema?: Record<string, TypeMeta>;
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
    const typeName = typeOptions[0] ?? "";
    const newItem: Record<string, string> = { [typeKey]: typeName };
    const meta = fieldSchema?.[typeName];
    if (meta) {
      for (const field of meta.fields) {
        if (field.required) {
          newItem[field.key] = field.default ?? "";
        }
      }
    }
    onChange([...items, newItem]);
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
            fieldSchema={fieldSchema}
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
  fieldSchema,
}: {
  typeKey: string;
  typeOptions: string[];
  item: Record<string, string>;
  onUpdate: (updated: Record<string, string>) => void;
  onRemove: () => void;
  fieldSchema?: Record<string, TypeMeta>;
}) {
  const typeName = item[typeKey] ?? "";
  const meta = fieldSchema?.[typeName];

  const [collapsedGroups, setCollapsedGroups] = useState<
    Record<string, boolean>
  >({});

  function toggleGroup(group: string) {
    setCollapsedGroups((prev) => ({ ...prev, [group]: !prev[group] }));
  }

  function setField(key: string, val: string) {
    onUpdate({ ...item, [key]: val });
  }

  function removeField(key: string) {
    const next = { ...item };
    delete next[key];
    onUpdate(next);
  }

  function onTypeChange(newType: string) {
    const newItem: Record<string, string> = { [typeKey]: newType };
    const newMeta = fieldSchema?.[newType];
    if (newMeta) {
      for (const field of newMeta.fields) {
        if (field.required) {
          newItem[field.key] = item[field.key] ?? field.default ?? "";
        }
      }
    }
    onUpdate(newItem);
  }

  if (!meta) {
    return (
      <GenericEntryCard
        typeKey={typeKey}
        typeOptions={typeOptions}
        item={item}
        onUpdate={onUpdate}
        onRemove={onRemove}
      />
    );
  }

  const knownKeySet = new Set(meta.fields.map((f) => f.key));
  const customKeys = Object.keys(item).filter(
    (k) => k !== typeKey && !knownKeySet.has(k),
  );

  const groups = groupFields(meta.fields);
  const presentKeys = new Set(Object.keys(item));
  const missingOptional = meta.fields.filter(
    (f) => !f.required && !presentKeys.has(f.key),
  );

  const hasOIDCFields =
    typeName === "HTTPX" &&
    meta.fields.some((f) => f.group === "OIDC / SSO");
  const oidcConfigured =
    hasOIDCFields &&
    Boolean(item["oidc_issuer"]?.trim()) &&
    Boolean(item["oidc_client_id"]?.trim());
  const oidcFieldsPresent =
    hasOIDCFields &&
    meta.fields
      .filter((f) => f.group === "OIDC / SSO")
      .some((f) => presentKeys.has(f.key));

  return (
    <div className="rounded-md border p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Label className="w-20 shrink-0 font-medium">{typeKey}</Label>
        <select
          className="h-9 flex-1 rounded-md border border-input bg-transparent px-2 text-sm"
          value={typeName}
          onChange={(e) => onTypeChange(e.target.value)}
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

      {hasOIDCFields && !oidcFieldsPresent && (
        <button
          type="button"
          className="w-full rounded-md border border-dashed border-blue-400/50 bg-blue-500/5 px-4 py-3 text-left text-sm hover:bg-blue-500/10 transition-colors"
          onClick={() => {
            const oidcFields = meta.fields.filter(
              (f) => f.group === "OIDC / SSO",
            );
            const updates: Record<string, string> = {};
            for (const f of oidcFields) {
              updates[f.key] = f.default ?? "";
            }
            onUpdate({ ...item, ...updates });
          }}
        >
          <span className="font-medium text-blue-700 dark:text-blue-400">
            Enable OIDC / SSO
          </span>
          <span className="block text-xs text-muted-foreground mt-0.5">
            Add single sign-on fields — just fill in Issuer URL and Client ID
            from your identity provider
          </span>
        </button>
      )}

      {groups.map(([groupName, fields]) => {
        const groupFieldsPresent = fields.filter((f) =>
          presentKeys.has(f.key),
        );
        const allGroupFields = fields;
        const isCollapsed = collapsedGroups[groupName] ?? false;

        if (groupFieldsPresent.length === 0 && groupName !== "") return null;

        return (
          <div key={groupName} className="space-y-2">
            {groupName && (
              <button
                type="button"
                className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
                onClick={() => toggleGroup(groupName)}
              >
                <span
                  className="transition-transform inline-block"
                  style={{
                    transform: isCollapsed ? "rotate(-90deg)" : "rotate(0deg)",
                  }}
                >
                  ▾
                </span>
                {groupName}
                {oidcConfigured && groupName === "OIDC / SSO" && (
                  <span className="ml-1 rounded bg-green-600/15 px-1.5 py-0.5 text-[10px] font-medium text-green-700 dark:text-green-400 normal-case tracking-normal">
                    configured
                  </span>
                )}
              </button>
            )}
            {!isCollapsed &&
              allGroupFields.map((field) => {
                if (!presentKeys.has(field.key)) return null;
                return (
                  <FieldRow
                    key={field.key}
                    field={field}
                    value={item[field.key] ?? ""}
                    onChange={(val) => setField(field.key, val)}
                    onRemove={
                      field.required
                        ? undefined
                        : () => removeField(field.key)
                    }
                  />
                );
              })}
          </div>
        );
      })}

      {customKeys.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            Custom fields
          </p>
          {customKeys.map((key) => (
            <div key={key} className="flex items-end gap-2 pl-2">
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
        </div>
      )}

      {(missingOptional.length > 0 || true) && (
        <AddFieldMenu
          missingFields={missingOptional}
          onAddKnown={(field) =>
            setField(field.key, field.default ?? "")
          }
          onAddCustom={() => onUpdate({ ...item, "": "" })}
        />
      )}
    </div>
  );
}

function FieldRow({
  field,
  value,
  onChange,
  onRemove,
}: {
  field: FieldMeta;
  value: string;
  onChange: (val: string) => void;
  onRemove?: () => void;
}) {
  return (
    <div className="flex items-start gap-2 pl-2">
      <div className="space-y-1 flex-1">
        <Label className="text-sm">
          {field.label}
          {field.required && (
            <span className="text-destructive ml-0.5">*</span>
          )}
        </Label>
        {field.description && (
          <p className="text-xs text-muted-foreground">{field.description}</p>
        )}
        <Input
          type={field.sensitive ? "password" : "text"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.default ?? ""}
        />
      </div>
      {onRemove && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="mt-6 shrink-0"
          onClick={onRemove}
        >
          Remove
        </Button>
      )}
    </div>
  );
}

function AddFieldMenu({
  missingFields,
  onAddKnown,
  onAddCustom,
}: {
  missingFields: FieldMeta[];
  onAddKnown: (field: FieldMeta) => void;
  onAddCustom: () => void;
}) {
  const [open, setOpen] = useState(false);

  if (missingFields.length === 0) {
    return (
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="ml-2"
        onClick={onAddCustom}
      >
        + Custom field
      </Button>
    );
  }

  const grouped = groupFields(missingFields);

  return (
    <div className="relative ml-2">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => setOpen(!open)}
      >
        + Add field
      </Button>
      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
          />
          <div className="absolute left-0 top-full z-50 mt-1 w-72 rounded-md border bg-popover shadow-lg max-h-80 overflow-y-auto">
            {grouped.map(([groupName, fields]) => (
              <div key={groupName}>
                {groupName && (
                  <p className="px-3 pt-2 pb-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                    {groupName}
                  </p>
                )}
                {fields.map((field) => (
                  <button
                    key={field.key}
                    type="button"
                    className="w-full px-3 py-1.5 text-left text-sm hover:bg-accent transition-colors"
                    onClick={() => {
                      onAddKnown(field);
                      setOpen(false);
                    }}
                  >
                    <span className="font-medium">{field.label}</span>
                    {field.description && (
                      <span className="block text-xs text-muted-foreground truncate">
                        {field.description}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            ))}
            <div className="border-t">
              <button
                type="button"
                className="w-full px-3 py-1.5 text-left text-sm hover:bg-accent transition-colors text-muted-foreground"
                onClick={() => {
                  onAddCustom();
                  setOpen(false);
                }}
              >
                Custom field…
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function GenericEntryCard({
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

  return (
    <div className="rounded-md border p-3 space-y-2">
      <div className="flex items-center gap-2">
        <Label className="w-20 shrink-0">{typeKey}</Label>
        <select
          className="h-9 flex-1 rounded-md border border-input bg-transparent px-2 text-sm"
          value={item[typeKey] ?? ""}
          onChange={(e) => onUpdate({ [typeKey]: e.target.value })}
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
        onClick={() => onUpdate({ ...item, "": "" })}
      >
        Add field
      </Button>
    </div>
  );
}

function groupFields(fields: FieldMeta[]): [string, FieldMeta[]][] {
  const map = new Map<string, FieldMeta[]>();
  for (const f of fields) {
    const group = f.group ?? "";
    const arr = map.get(group);
    if (arr) {
      arr.push(f);
    } else {
      map.set(group, [f]);
    }
  }
  return Array.from(map.entries());
}

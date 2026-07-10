import { cn } from "@/lib/utils";
import { useCopy } from "@/lib/useCopy";
import type { InteractionDetail } from "@/lib/types";

function ClipboardIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

// CopyButton copies text to the clipboard and briefly confirms.
export function CopyButton({ text, label }: { text: string; label: string }) {
  const { copied, copy } = useCopy();
  return (
    <button
      type="button"
      onClick={() => copy(text)}
      aria-label={label}
      title={copied ? "Copied!" : label}
      className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-md border bg-background/80 px-1.5 py-1 text-xs text-muted-foreground backdrop-blur hover:text-foreground"
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  );
}

// CodeBlock renders monospace text with a copy-to-clipboard button.
export function CodeBlock({
  text,
  copyLabel,
  className,
}: {
  text: string;
  copyLabel: string;
  className?: string;
}) {
  return (
    <div className="relative">
      <CopyButton text={text} label={copyLabel} />
      <pre
        className={cn(
          "overflow-auto rounded-md bg-muted p-3 pr-12 text-xs",
          className,
        )}
      >
        {text}
      </pre>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono">{value}</div>
    </div>
  );
}

// InteractionDetailView renders a single interaction's full detail: metadata
// plus a replay curl, raw request, and body. Each code block is shown only when
// it has content — non-httpx handlers (dns/tcp/smb/…) have no replay curl and
// no raw HTTP request dump, so those blocks are omitted rather than left empty.
export function InteractionDetailView({ d }: { d: InteractionDetail }) {
  const hasCurl = (d.curl ?? "").trim() !== "";
  const hasHeaders = (d.headers ?? "").trim() !== "";
  const hasBody = (d.body ?? "").trim() !== "";
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
        <Field label="Source" value={`${d.remote_addr}:${d.remote_port}`} />
        <Field label="Protocol" value={d.protocol} />
        <Field label="Handler" value={d.handler} />
        <Field label="Time" value={new Date(d.created_at).toLocaleString()} />
      </div>

      {hasCurl && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Replay
          </div>
          <CodeBlock text={d.curl.trim()} copyLabel="Copy as curl" />
        </div>
      )}

      {hasHeaders && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Raw request
          </div>
          <CodeBlock
            text={d.headers}
            copyLabel="Copy raw request"
            className="max-h-96"
          />
        </div>
      )}

      {hasBody && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Body
          </div>
          <CodeBlock text={d.body} copyLabel="Copy body" className="max-h-96" />
        </div>
      )}
    </div>
  );
}

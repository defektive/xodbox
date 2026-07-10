// The admin UI is served under a configurable path prefix (ui_path). The Go
// server injects the resolved prefix into index.html as the #root element's
// data-xodbox-base attribute (e.g. "/admin/"). We read it from the DOM rather
// than an inline script so the strict CSP (script-src 'self') needs no
// 'unsafe-inline'/nonce. Everything — router basename and API calls — derives
// from it so the same compiled bundle works at any mount point.
function readInjectedBase(): string {
  const el =
    typeof document !== "undefined" ? document.getElementById("root") : null;
  return el?.dataset.xodboxBase ?? "/";
}

function normalize(p: string): string {
  if (!p) return "/";
  if (!p.startsWith("/")) p = "/" + p;
  if (!p.endsWith("/")) p = p + "/";
  return p;
}

// basePath ends with a trailing slash, e.g. "/admin/". In dev (or if the Go
// server placeholder wasn't substituted) it falls back to "/".
const raw = readInjectedBase();
export const basePath = normalize(raw.includes("{{") ? "/" : raw);

// routerBasename has no trailing slash (react-router convention), e.g. "/admin".
export const routerBasename =
  basePath === "/" ? "/" : basePath.replace(/\/$/, "");

// apiBase is where the admin JSON API is mounted, e.g. "/admin/api/".
export const apiBase = basePath + "api/";

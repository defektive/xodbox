// The admin UI is served under a configurable path prefix (ui_path). The Go
// server injects the resolved prefix into index.html as window.__XODBOX_BASE__
// (e.g. "/admin/"). Everything — router basename and API calls — derives from
// it so the same compiled bundle works at any mount point.
declare global {
  interface Window {
    __XODBOX_BASE__?: string;
  }
}

function normalize(p: string): string {
  if (!p) return "/";
  if (!p.startsWith("/")) p = "/" + p;
  if (!p.endsWith("/")) p = p + "/";
  return p;
}

// basePath ends with a trailing slash, e.g. "/admin/". In dev (or if the Go
// server placeholder wasn't substituted) it falls back to "/".
const raw = window.__XODBOX_BASE__ ?? "/";
export const basePath = normalize(raw.includes("{{") ? "/" : raw);

// routerBasename has no trailing slash (react-router convention), e.g. "/admin".
export const routerBasename =
  basePath === "/" ? "/" : basePath.replace(/\/$/, "");

// apiBase is where the admin JSON API is mounted, e.g. "/admin/api/".
export const apiBase = basePath + "api/";

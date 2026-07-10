package httpx

import "embed"

// embeddedUIFS holds the compiled admin SPA (Vite/React build output). The
// assets are committed under webui/ so `go build`, CI, and tests work without
// a Node toolchain present; regenerate them with `make ui`.
//
//go:embed all:webui
var embeddedUIFS embed.FS

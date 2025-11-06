package httpx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

type ReqHeader http.Header

func (rh RequestStruct) MarshalXML(e *xml.Encoder, start xml.StartElement) error {

	requestTag := []xml.Token{start}

	method := xml.StartElement{Name: xml.Name{Local: "method"}}
	requestTag = append(requestTag, method, xml.CharData(rh.Method), xml.EndElement{Name: method.Name})

	path := xml.StartElement{Name: xml.Name{Local: "path"}}
	requestTag = append(requestTag, path, xml.CharData(rh.Path), xml.EndElement{Name: path.Name})

	remoteAddr := xml.StartElement{Name: xml.Name{Local: "remoteAddr"}}
	requestTag = append(requestTag, remoteAddr, xml.CharData(rh.RemoteAddr), xml.EndElement{Name: remoteAddr.Name})

	body := xml.StartElement{Name: xml.Name{Local: "body"}}
	requestTag = append(requestTag, body, xml.CharData(rh.Body), xml.EndElement{Name: body.Name})

	headersTag := xml.StartElement{Name: xml.Name{Local: "headers"}}
	requestTag = append(requestTag, headersTag)
	for key, values := range rh.Headers {
		for _, value := range values {
			t := xml.StartElement{Name: xml.Name{Local: key}}
			requestTag = append(requestTag, t, xml.CharData(value), xml.EndElement{Name: t.Name})
		}
	}

	requestTag = append(requestTag, xml.EndElement{Name: headersTag.Name})
	requestTag = append(requestTag, xml.EndElement{Name: start.Name})

	for _, t := range requestTag {
		err := e.EncodeToken(t)
		if err != nil {
			return err
		}
	}

	// flush to ensure tokens are written
	return e.Flush()
}

type RequestStruct struct {
	Method     string              `xml:"method" json:"method"`
	Path       string              `xml:"path" json:"path"`
	RemoteAddr string              `xml:"remote_addr" json:"remote_addr"`
	Headers    map[string][]string `xml:"headers" json:"headers"`
	Body       string              `xml:"body" json:"body"`
}

func Inspect(w http.ResponseWriter, e *Event) error {

	r := e.Request()

	fullRequestBytes := e.RawRequest()
	requestStr := string(fullRequestBytes)

	if strings.HasSuffix(r.URL.Path, ".png") {
		return toPNG(w, r, requestStr)
	}

	if strings.HasSuffix(r.URL.Path, ".gif") {
		return toGIF(w, r, requestStr)
	}

	if strings.HasSuffix(r.URL.Path, ".jpg") {
		return toJPG(w, r, requestStr)
	}

	// text based responses, default txt
	contentType := "text/plain; charset=utf-8"
	fmtString := "Text Request\n\n%s"
	outputString := requestStr

	myRequest := RequestStruct{
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		Headers:    r.Header,
		Body:       string(e.Body()),
	}

	if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, ".htm") {
		contentType = "text/html; charset=utf-8"
		fmtString = "<html><head></head><body><h1>HTML Request</h1><pre>%s</pre></body></html>"
		outputString = html.EscapeString(outputString)
	} else if strings.HasSuffix(r.URL.Path, ".json") {
		contentType = "application/json; charset=utf-8"

		if r.URL.Query().Has("array") {
			fmtString = "[%s]"
		} else {
			fmtString = "%s"
		}

		jsonBytes, err := json.Marshal(myRequest)
		if err != nil {
			return err
		}
		outputString = string(jsonBytes)
	} else if strings.HasSuffix(r.URL.Path, ".xml") {
		contentType = "text/xml; charset=utf-8"
		fmtString = "%s"
		xmlBytes, err := xml.Marshal(myRequest)
		if err != nil {
			return err
		}
		outputString = string(xmlBytes)
	} else if strings.HasSuffix(r.URL.Path, ".js") {
		contentType = "application/javascript; charset=utf-8"
		fmtString = "let reqResponse = %s"
		jsonBytes, err := json.Marshal(myRequest)
		if err != nil {
			return err
		}
		outputString = string(jsonBytes)
	}

	w.Header().Set("Content-Type", contentType)
	_, err := fmt.Fprintf(w, fmtString, outputString)
	return err
}

func createImage(w http.ResponseWriter, r *http.Request, requestStr string) *image.CMYK {

	lineHeight := 15
	characterWidth := 7

	resData := strings.Split(requestStr, "\n")
	maxLen := 0
	for _, v := range resData {
		ml := len(v)
		if ml > maxLen {
			maxLen = ml
		}
	}

	img := image.NewCMYK(image.Rect(0, 0, (2*lineHeight)+(maxLen*characterWidth), (2*lineHeight)+(len(resData)*lineHeight)))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	for i, v := range resData {
		addLabel(img, lineHeight, (i*lineHeight)+30, v)
	}

	return img
}

func toPNG(w http.ResponseWriter, r *http.Request, requestStr string) error {
	w.Header().Set("Content-Type", "image/png")
	img := createImage(w, r, requestStr)
	return png.Encode(w, img)
}

func toJPG(w http.ResponseWriter, r *http.Request, requestStr string) error {
	w.Header().Set("Content-Type", "image/jpeg")
	img := createImage(w, r, requestStr)
	return jpeg.Encode(w, img, &jpeg.Options{Quality: 80})
}

func toGIF(w http.ResponseWriter, r *http.Request, requestStr string) error {

	w.Header().Set("Content-Type", "image/gif")
	img := createImage(w, r, requestStr)
	return gif.Encode(w, img, &gif.Options{NumColors: 256})
}

func addLabel(img *image.CMYK, x, y int, label string) {
	col := color.RGBA{A: 255}
	point := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}

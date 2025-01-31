package httpx

import (
	"fmt"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"html"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strings"
)

type RequestReflectionPayload struct {
}

func (h *RequestReflectionPayload) ShouldHandle(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/inspect")
}

func (h *RequestReflectionPayload) Process(w http.ResponseWriter, r *http.Request) {
	rr := NewRequestResponse(r)

	lineHeight := 15
	characterWidth := 7

	if strings.HasSuffix(r.URL.Path, ".png") || strings.HasSuffix(r.URL.Path, ".gif") || strings.HasSuffix(r.URL.Path, ".jpg") {
		resData := strings.Split(rr.Text(), "\n")
		maxLen := 0
		for _, v := range resData {
			ml := len(v)
			if ml > maxLen {
				maxLen = ml
			}
		}

		img := image.NewCMYK(image.Rect(0, 0, (2*lineHeight)+(maxLen*characterWidth), (2*lineHeight)+(len(resData)*lineHeight)))
		draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.Point{0, 0}, draw.Src)
		for i, v := range resData {
			addLabel(img, lineHeight, (i*lineHeight)+30, v)
		}

		var err error

		if strings.HasSuffix(r.URL.Path, ".png") {
			w.Header().Set("Content-Type", "image/png")
			err = png.Encode(w, img)
		}

		if strings.HasSuffix(r.URL.Path, ".gif") {
			w.Header().Set("Content-Type", "image/gif")
			err = gif.Encode(w, img, &gif.Options{NumColors: 256})
		}

		if strings.HasSuffix(r.URL.Path, ".jpg") {
			w.Header().Set("Content-Type", "image/jpeg")
			err = jpeg.Encode(w, img, &jpeg.Options{Quality: 80})
		}

		if err != nil {
			lg().Error("error encoding image", "err", err)
		} else {
			return
		}
	}

	if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, ".htm") {

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		htmlRes := fmt.Sprintf("<html><head></head><body><h1>HTML Request</h1><pre>%s</pre></body></html>", html.EscapeString(rr.Text()))
		fmt.Fprint(w, htmlRes)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, fmt.Sprintf("Text Request\n\n%s", rr.Text()))
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

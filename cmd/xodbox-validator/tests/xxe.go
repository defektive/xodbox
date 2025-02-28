package tests

import (
	"github.com/lestrrat-go/libxml2/parser"
	"io"
	"log"
	"net/http"
	"strings"
)

func XXE() {
	if !strings.Contains(VulnProcessURLXML("http://localhost/l/dt"), "I should be loaded from") {
		log.Println("failed: response does not contain xxe response")
	} else {
		log.Println("succeeded: response contains xxe response")
	}
}

func VulnProcessURLXML(url string) string {
	log.Println("Getting XML from url:", url)
	b, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer b.Body.Close()
	return VulnProcessReaderXML(b.Body)
}

func VulnProcessReaderXML(r io.Reader) string {
	p := parser.New(parser.XMLParseNoEnt)

	log.Println("processing reader xml")
	doc, err := p.ParseReader(r)
	if err != nil {
		panic(err)
	}
	defer doc.Free()
	log.Println("done processing reader", doc.String())

	return doc.String()
}

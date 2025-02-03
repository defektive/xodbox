package tests

import (
	"fmt"
	"github.com/lestrrat-go/libxml2/parser"
	"net/http"
)

func XXE() {

	b, err := http.Get("http://localhost/l/dt")
	if err != nil {
		panic(err)
	}

	defer b.Body.Close()
	// parse the XML body
	p := parser.New(parser.XMLParseNoEnt)
	doc, err := p.ParseReader(b.Body)
	defer doc.Free()

	fmt.Println(doc.String())

}

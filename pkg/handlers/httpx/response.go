package httpx

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

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

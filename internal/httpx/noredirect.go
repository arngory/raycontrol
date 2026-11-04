// Package httpx holds small HTTP helpers shared by rayd's endpoints.
package httpx

import (
	"net/http"
)

// NoRedirect serves h but never answers with a redirect: a 3xx that h (or
// net/http's ServeMux, for a path without its trailing slash or one to
// clean) would send becomes a 404 without a Location. Niko treats a 3xx from
// the subscription, the API and the probes as an error (RAYCONTROL.md §22),
// and the node has nowhere to send anyone.
func NoRedirect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(&noRedirect{ResponseWriter: w}, r)
	})
}

type noRedirect struct {
	http.ResponseWriter
	dropped bool // a redirect turned into a 404: its body is not sent
}

func (n *noRedirect) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		n.Header().Del("Location")
		n.Header().Del("Content-Type")
		n.dropped = true
		n.ResponseWriter.WriteHeader(http.StatusNotFound)
		return
	}
	n.ResponseWriter.WriteHeader(code)
}

func (n *noRedirect) Write(b []byte) (int, error) {
	if n.dropped {
		return len(b), nil
	}
	return n.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer
// (flushing, deadlines).
func (n *noRedirect) Unwrap() http.ResponseWriter { return n.ResponseWriter }

// Flush passes on to the underlying writer, for handlers that assert
// http.Flusher.
func (n *noRedirect) Flush() {
	if f, ok := n.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

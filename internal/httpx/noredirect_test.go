package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe/v1/", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "probe") })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) })
	srv := httptest.NewServer(NoRedirect(mux))
	defer srv.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]int{
		"/probe/v1/x":  200,
		"/probe/v1":    404, // ServeMux would answer 301 to /probe/v1/
		"/a/../probe/": 404, // a path to clean: 301 from ServeMux
		"/moved":       404,
		"/nothing":     404,
	} {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want || resp.Header.Get("Location") != "" {
			t.Errorf("%s: %d %q location %q, want %d", path, resp.StatusCode, body, resp.Header.Get("Location"), want)
		}
	}
}

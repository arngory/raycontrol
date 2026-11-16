package release

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The error of a download through mirrors, as a relay's status would have
// it, names each mirror by its place: its URL, the user and password in it
// as net/http writes them, its host in a lookup and in a certificate's
// complaint, a subdomain of it. The default mirrors keep their names, and
// so do GitHub and a longer name that holds a mirror's.
func TestHideMirrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusBadGateway)
	}))
	defer srv.Close()
	mirrors := []string{"https://user:s3cret@Mirror.Corp.example:8443/gh/", "https://ghfast.top/", srv.URL + "/"}
	// No network: the mirrors but the last do not resolve.
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == srv.Listener.Addr().String() {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		host, _, _ := net.SplitHostPort(addr)
		return nil, &net.DNSError{Err: "no such host", Name: host, Server: "127.0.0.53:53", IsNotFound: true}
	}}}
	f := &Fetcher{Mirrors: mirrors, HTTP: hc}
	_, err := f.Get(context.Background(), "v0.29.0", "SHA256SUMS", 1<<16)
	if err == nil {
		t.Fatal("downloaded")
	}
	text := err.Error() + "; x509: certificate is valid for cdn.example, not mirror.corp.example; via cdn.mirror.corp.example. " +
		"Not mirror.corp.example.org, nor mirror.corp.examples."
	out := HideMirrors(text, mirrors)
	for _, leak := range []string{"user", "s3cret", "***", "xxxxx", "Mirror.Corp", "lookup mirror", "not mirror", "cdn.mirror", srv.Listener.Addr().String()} {
		if strings.Contains(out, leak) {
			t.Errorf("%q in %s", leak, out)
		}
	}
	for _, keep := range []string{`Get "<mirror 1 of 3>/https://github.com/arngory/raycontrol/releases/download/v0.29.0/SHA256SUMS"`,
		"lookup <mirror 1 of 3> on", "lookup github.com", "lookup ghfast.top", `Get "https://ghfast.top/https://github.com/`,
		"<mirror 3 of 3>/https://github.com/arngory/raycontrol/releases/download/v0.29.0/SHA256SUMS: 502 Bad Gateway",
		"not <mirror 1 of 3>;", "via cdn.<mirror 1 of 3>.", "Not mirror.corp.example.org, nor mirror.corp.examples."} {
		if !strings.Contains(out, keep) {
			t.Errorf("no %q in %s", keep, out)
		}
	}
	if HideMirrors(text, nil) != text || HideMirrors(text, []string{"not a url", ""}) != text {
		t.Error("changed with no mirror in it")
	}
}

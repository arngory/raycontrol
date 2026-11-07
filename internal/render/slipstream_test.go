package render_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path"
	"slices"
	"strings"
	"testing"

	nodepkg "github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// A slipstream service (spec/slipstream-v1.md §2): its zone in the front
// with the tag check, the probe and the apex, the devices' keys in a file
// of the front's that it rereads; its certificate in place and its key for
// systemd to copy; the server's arguments.
func TestRenderSlipstream(t *testing.T) {
	st := node(t)
	ctx := context.Background()
	slip, err := provision.CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, _ := st.ServiceByName(ctx, "dns")
	mdns, _ := st.ServiceByName(ctx, "mdns")
	st.SetUserServices(ctx, "alice", []int64{dns.ID, mdns.ID, slip.ID})
	dev, key, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateDevice(ctx, "bob", "laptop", "user"); err != nil { // bob is not on it
		t.Fatal(err)
	}
	ss, err := provision.ParseSlipstream(slip)
	if err != nil {
		t.Fatal(err)
	}

	// Without the devices' keys it is left out: an empty file would lock
	// every device out.
	m, _ := render.Collect(ctx, st)
	if _, _, err := render.Render(m, render.DefaultPaths); !render.Partial(err) || !strings.Contains(err.Error(), "service slip: dnsauth keys not collected") {
		t.Fatalf("without the keys: %v", err)
	}

	m, err = render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	p := render.DefaultPaths
	files, _, err := render.Render(m, p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]render.File{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	dir := path.Join(p.Rendered, "slip")
	cert, ok := byPath[path.Join(dir, render.SlipstreamCert)]
	if !ok || cert.Mode != 0o640 || cert.Group != "niko-slip" || cert.Service != "slip" || cert.Reload {
		t.Errorf("certificate %+v", cert)
	}
	b, _ := pem.Decode(cert.Content)
	secrets, _ := st.ServiceSecrets(ctx, slip.ID)
	if b == nil || b.Type != "CERTIFICATE" || string(b.Bytes) != string(secrets[provision.SecretTLSCert]) {
		t.Errorf("certificate PEM %q", cert.Content)
	}
	keyFile, ok := byPath[path.Join(dir, render.SlipstreamKey)]
	if !ok || keyFile.Mode != 0o600 || keyFile.Group != "" || keyFile.Service != "slip" {
		t.Errorf("key %+v", keyFile.Path)
	}
	if b, _ := pem.Decode(keyFile.Content); b == nil || b.Type != "PRIVATE KEY" {
		t.Error("key PEM")
	} else if _, err := x509.ParsePKCS8PrivateKey(b.Bytes); err != nil {
		t.Error(err)
	}
	// No niko-server backend config for it: the server takes arguments.
	if _, ok := byPath[path.Join(dir, "backend.json")]; ok {
		t.Error("backend.json for slipstream")
	}

	// The devices' keys, the front's: alice's phone only, no line of the
	// node (its check asks the front only).
	auth, ok := byPath[p.FrontAuthKeys("slip")]
	if !ok || auth.Mode != 0o640 || auth.Group != "niko-front" || auth.Service != "front" || !auth.Reload ||
		auth.Path != "/var/lib/raycontrol/rendered/front/slip.auth.keys" {
		t.Fatalf("front keys %+v", auth)
	}
	params, _ := nodepkg.LoadParams(ctx, st)
	k := spa.DNSAuthKey(key, params.NodeID, uint16(slip.ID))
	if !strings.Contains(string(auth.Content), dev.ID+" "+hex.EncodeToString(k[:])+"\n") || strings.Count(string(auth.Content), "\n") != 2 ||
		strings.Contains(string(auth.Content), provision.DNSCheckDevice) {
		t.Errorf("front keys:\n%s", auth.Content)
	}

	type zone struct {
		Zone         string   `json:"zone"`
		Backend      string   `json:"backend"`
		Probe        bool     `json:"probe"`
		NS           []string `json:"ns"`
		SealPad      bool     `json:"seal_pad"`
		Tag          string   `json:"tag"`
		AuthKeysFile string   `json:"auth_keys_file"`
	}
	var front struct {
		Backends map[string]struct {
			Socket string `json:"socket"`
			Mode   string `json:"mode"`
		} `json:"backends"`
		DNS struct {
			Zones        []zone `json:"zones"`
			ProbeKeyFile string `json:"probe_key_file"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(byPath[path.Join(p.Rendered, "front", "front.json")].Content, &front); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(front.DNS.Zones, func(z zone) bool { return z.Backend == "slip" })
	if i < 0 {
		t.Fatalf("no zone of slip in %+v", front.DNS.Zones)
	}
	z := front.DNS.Zones[i]
	if z.Zone != ss.Zone || !z.Probe || len(z.NS) != 1 || z.NS[0] != m.NSName || z.SealPad || z.Tag != "slipstream" ||
		z.AuthKeysFile != auth.Path || front.DNS.ProbeKeyFile == "" {
		t.Errorf("front zone %+v", z)
	}
	// The other tunnels' zones carry no tag.
	for _, o := range front.DNS.Zones {
		if o.Backend != "slip" && (o.Tag != "" || o.AuthKeysFile != "") {
			t.Errorf("zone %+v", o)
		}
	}
	if b := front.Backends["slip"]; b.Socket != p.FrontSocket("slip", "packet") || b.Mode != "packet" {
		t.Errorf("backend %+v", b)
	}

	args, err := render.SlipstreamArgs(render.Service{Service: slip}, "inner", p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--front-socket", p.FrontSocket("slip", "packet"), "--front-uid", "9100", "--tag-len", "8",
		"--target-unix", p.InnerSocket("inner"), "--cert", path.Join(dir, render.SlipstreamCert),
		"--key", p.Credential("slip", render.SlipstreamKey), "--domain", ss.Zone, "--alpn", ss.ALPN}
	if !slices.Equal(args, want) {
		t.Errorf("args\n%q\nwant\n%q", args, want)
	}
	if got := render.UnservedZones(m); len(got) != 0 {
		t.Errorf("unserved %v", got)
	}

	// Broken settings leave it out of the front and of the subscription
	// (UnservedZones); the front's keys still go out, so a revoked device
	// loses the service at the front at once.
	if err := st.UpdateService(ctx, slip.ID, store.ServiceUpdate{Settings: `{"zone":"` + ss.Zone + `","quic_alpn":"x","quic_sni":"` + ss.SNI + `"}`}); err != nil {
		t.Fatal(err)
	}
	m, _ = render.CollectForRender(ctx, st)
	files, _, err = render.Render(m, p)
	if !render.Partial(err) || !strings.Contains(err.Error(), "service slip: quic_alpn") {
		t.Fatalf("broken settings: %v", err)
	}
	var refreshed bool
	for _, f := range files {
		if f.Path == p.FrontAuthKeys("slip") {
			refreshed = f.Refresh
		}
		if f.Service == "front" && strings.HasSuffix(f.Path, "front.json") && strings.Contains(string(f.Content), ss.Zone) {
			t.Error("the zone of a service left out is in the front")
		}
	}
	if !refreshed {
		t.Error("no refresh of the front's keys")
	}
	if got := render.UnservedZones(m); got[slip.ID] == nil {
		t.Errorf("unserved %v", got)
	}
}

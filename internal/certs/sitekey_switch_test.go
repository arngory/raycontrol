package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// The operator's switch gets its order at once (spec/cert-pin-v1.md §5),
// also for a site in a back-off after failed renewals: a leaked key served
// up to a day longer while rayctl said the order was made now. One try a
// request; if that fails too, the back-off goes on.
func TestManagerSwitchPastBackoff(t *testing.T) {
	ctx := context.Background()
	start := time.Unix(1767225600, 0)
	now := start
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state()

	// Renewals fail for a while (a rate limit, DNS): the back-off is a day.
	n.fail = true
	now = start.Add(61 * day)
	for range 6 {
		now = now.Add(25 * time.Hour)
		n.m.Once(ctx, now)
	}
	now = now.Add(time.Minute)
	if wait := n.m.next["site"].Sub(now); wait < 20*time.Hour {
		t.Fatalf("the site waits %v only", wait)
	}
	// The key leaked: root forces the switch. The CA still fails: the one
	// try is made, and the wait goes on from it.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchForce); err != nil {
		t.Fatal(err)
	}
	fails := n.m.fails["site"]
	n.m.Once(ctx, now)
	if n.m.fails["site"] != fails+1 {
		t.Fatalf("no try for the forced switch in the back-off: failures %d, before %d", n.m.fails["site"], fails)
	}
	n.fail = false
	if n.m.Once(ctx, now.Add(time.Minute)); n.issued != 1 || n.state().leafPin != first.leafPin {
		t.Fatal("a second try within the back-off for the same request")
	}
	// Another site in a back-off, the CA in order again: ordered at once.
	n2 := newSiteNode(t, provision.SiteKeyPolicy{})
	now2 := start
	n2.at(ca, &now2)
	n2.m.Once(ctx, now2)
	first2 := n2.state()
	n2.fail = true
	now2 = start.Add(61 * day)
	for range 6 {
		now2 = now2.Add(25 * time.Hour)
		n2.m.Once(ctx, now2)
	}
	n2.fail = false
	now2 = now2.Add(time.Minute)
	if err := provision.RequestSiteKeyRotation(ctx, n2.st, "site", now2, 14*day, provision.SiteSwitchForce); err != nil {
		t.Fatal(err)
	}
	if got := n2.m.Once(ctx, now2); got != 1 || n2.state().leafPin != first2.pins[1] {
		t.Fatalf("the forced switch was not ordered at once: stored %d, the next try in %v", got, n2.m.next["site"].Sub(now2))
	}
}

// A request is its time and its way: a waiting -force upgraded to -fresh
// keeps the time and got no try of its own, so it waited out the back-off
// of the failed one, up to a day, while rayctl said "one try now". The
// same request again gets a try RetryGap after the last at the earliest
// (Manager.RetrySite, run by the API at every request), not at once.
func TestManagerSwitchAskedAgain(t *testing.T) {
	ctx := context.Background()
	start := time.Unix(1767225600, 0)
	now := start
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state()
	ask := func(how string) {
		t.Helper()
		if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, how); err != nil {
			t.Fatal(err)
		}
		n.m.RetrySite("site")
	}

	// The CA fails for days: the back-off is a day.
	n.fail = true
	now = start.Add(61 * day)
	for range 6 {
		now = now.Add(25 * time.Hour)
		n.m.Once(ctx, now)
	}
	now = now.Add(time.Minute)
	// -force: its one try fails.
	ask(provision.SiteSwitchForce)
	fails := n.m.fails["site"]
	n.m.Once(ctx, now)
	if n.m.fails["site"] != fails+1 {
		t.Fatal("no try for the forced switch")
	}
	// -force again five minutes later: no try within RetryGap of the last.
	now = now.Add(5 * time.Minute)
	ask(provision.SiteSwitchForce)
	n.m.Once(ctx, now)
	if n.m.fails["site"] != fails+1 {
		t.Fatal("the same request again was tried within RetryGap of the last try")
	}
	// Due RetryGap after the last try, not after the back-off of a day.
	if at := n.m.next["site"]; !at.Equal(now.Add(-5*time.Minute + RetryGap)) {
		t.Fatalf("the repeat is tried in %v", at.Sub(now))
	}
	now = now.Add(RetryGap)
	n.m.Once(ctx, now)
	if n.m.fails["site"] != fails+2 {
		t.Fatal("the same request again got no try after RetryGap")
	}
	// The CA works again a minute later, and the store leaked too:
	// -fresh, a request of its own, is ordered at once.
	n.fail = false
	now = now.Add(time.Minute)
	ask(provision.SiteSwitchFresh)
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("the upgraded request got no try: the next is in %v", n.m.next["site"].Sub(now))
	}
	if s := n.state(); s.leafPin == first.leafPin || slices.Contains(first.pins, s.leafPin) {
		t.Fatalf("-fresh serves a key of before: %s", s.leafPin)
	}
}

// -force again a minute after the switch it asked for was made would
// switch once more, to a key made a minute ago: clients that hold [A, B]
// would meet C. Refused while the key in use is younger than a
// subscription lives; a key for the order (-fresh) is the way then, and it
// says what it costs. A request that waits is answered as done whatever is
// asked again, before any check of the time.
func TestManagerForceTwice(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state() // [A, B]
	now = now.Add(20 * day)

	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchForce); err != nil {
		t.Fatal(err)
	}
	// While it waits (the order fails): the same again, and a plain request
	// 20 days in, which alone would be too early for a younger key, both
	// get the answer of the first.
	n.fail = true
	n.m.Once(ctx, now)
	for _, how := range []string{provision.SiteSwitchForce, provision.SiteSwitchLead} {
		if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now.Add(time.Minute), 30*day, how); err != nil {
			t.Fatalf("asked again (%q) while the request waits: %v", how, err)
		}
	}
	if s := n.state().keys; s.RotateAt != now.Unix() || s.RotateHow != provision.SiteSwitchForce {
		t.Fatalf("the waiting request changed: %+v", s)
	}
	n.fail = false
	now = now.Add(2 * time.Hour)
	if got := n.m.Once(ctx, now); got != 1 || n.state().leafPin != first.pins[1] {
		t.Fatalf("the forced switch: stored %d", got)
	}
	// Forced: the key before leaked, its pin is not kept in the lists.
	second := n.state()
	if len(second.pins) != 2 || second.keys.PrevPin != "" {
		t.Fatalf("pins after a forced switch: %v", second.pins)
	}

	// A minute later, and a second before the 72 hours are over.
	for _, at := range []time.Time{now.Add(time.Minute), now.Add(provision.SiteKeyMinAge - time.Second)} {
		err := provision.RequestSiteKeyRotation(ctx, n.st, "site", at, 14*day, provision.SiteSwitchForce)
		if !errors.Is(err, store.ErrPrecondition) || !strings.Contains(err.Error(), "-fresh") {
			t.Fatalf("a second forced switch %v after the first: %v", at.Sub(now), err)
		}
	}
	n.m.Once(ctx, now.Add(time.Minute))
	if s := n.state(); s.leafPin != second.leafPin || !slices.Contains(first.pins, s.leafPin) {
		t.Fatalf("the node serves a key outside the list [A, B] a client holds: %s", s.leafPin)
	}
	// After 72 hours every list in use has the next key: forced again works.
	now = now.Add(provision.SiteKeyMinAge)
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchForce); err != nil {
		t.Fatalf("forced again after 72 hours: %v", err)
	}
	if got := n.m.Once(ctx, now); got != 1 || n.state().leafPin != second.pins[1] {
		t.Fatalf("the second forced switch: stored %d", got)
	}
}

// -fresh (§5): the store leaked, so the next key did too. The certificate
// moves to a key made for the order and the next key is replaced: none of
// the pins of before is served or published again, the key before is not
// kept in the lists, and no lead or age is asked.
func TestManagerFreshKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	// Before the first certificate there is nothing to leave.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchFresh); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("without a certificate: %v", err)
	}
	n.m.Once(ctx, now)
	first := n.state()
	now = now.Add(time.Minute) // the key a minute old, the next one too
	// A plain request waits; -fresh over it takes its place.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 0, provision.SiteSwitchLead); err != nil {
		t.Fatal(err)
	}
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchFresh); err != nil {
		t.Fatal(err)
	}
	if s := n.state().keys; s.RotateHow != provision.SiteSwitchFresh {
		t.Fatalf("the request: %+v", s)
	}
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("the fresh key: stored %d", got)
	}
	s := n.state()
	if len(s.pins) != 2 || slices.Contains(first.pins, s.pins[0]) || slices.Contains(first.pins, s.pins[1]) {
		t.Fatalf("pins after a fresh key %v, before %v: a key of before is still pinned", s.pins, first.pins)
	}
	if s.leafPin != s.pins[0] || bytes.Equal(s.key, first.key) || bytes.Equal(s.key, first.next) || bytes.Equal(s.next, first.next) {
		t.Fatal("a key of before is still in the store's two")
	}
	if s.keys.RotateAt != 0 || s.keys.RotateHow != "" || s.keys.PrevPin != "" || s.keys.KeyAt != now.Unix() || s.keys.NextAt != now.Unix() {
		t.Fatalf("state after a fresh key: %+v", s.keys)
	}
	if got := n.m.Once(ctx, now.Add(time.Hour)); got != 0 {
		t.Fatal("ordered again")
	}
}

// The request holds to the next key it was checked against by that key's
// pin, not by comparing times: a clock set back between the request and the
// order (an NTP step) must not drop a forced switch without a word.
func TestManagerSwitchWithClockSetBack(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state()
	// The next key was made on a clock a day ahead of the one the request
	// comes on. The key in use is old enough by its record.
	now = now.Add(-day)
	svc, _ := n.st.ServiceByName(ctx, "site")
	settings := strings.Replace(svc.Settings, fmt.Sprintf(`"tls_key_at":%d`, first.keys.KeyAt), fmt.Sprintf(`"tls_key_at":%d`, now.Add(-30*day).Unix()), 1)
	if err := n.st.UpdateService(ctx, n.id, store.ServiceUpdate{Settings: settings}); err != nil {
		t.Fatal(err)
	}
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchForce); err != nil {
		t.Fatal(err)
	}
	if s := n.state().keys; s.RotateAt >= s.NextAt || s.RotatePin != first.pins[1] {
		t.Fatalf("the request: %+v", s)
	}
	if got := n.m.Once(ctx, now); got != 1 || n.state().leafPin != first.pins[1] {
		t.Fatalf("a forced switch asked on a clock behind the next key's time was dropped: stored %d", got)
	}
}

func pemBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

// Notify (rayd renders, restarts, DoH takes the certificate) comes with
// each certificate stored, not after the pass: with two sites the first
// one's new pins were in every subscription for as long as the second
// one's order took, and nothing had told the processes.
func TestManagerNotifiesAfterEachSite(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	if _, err := provision.CreateService(ctx, n.st, store.Service{Kind: "site", Name: "site2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ca, _ := testCA()
	n.at(ca, &now)
	notified := 0
	n.m.Notify = func() { notified++ }
	if got := n.m.Once(ctx, now); got != 2 || notified != 2 {
		t.Fatalf("first certificates: stored %d, notified %d", got, notified)
	}
	first := n.state()
	now = now.Add(20 * day)
	for _, site := range []string{"site", "site2"} {
		if err := provision.RequestSiteKeyRotation(ctx, n.st, site, now, 14*day, provision.SiteSwitchLead); err != nil {
			t.Fatal(err)
		}
	}
	notified = 0
	calls := 0
	n.m.Issue = func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		calls++
		// The second site's order begins (ACME: seconds to minutes).
		if s := n.state(); calls == 2 && (s.leafPin == first.leafPin || notified != 1) {
			t.Errorf("at the second site's order: the first switched %v, notified %d times", s.leafPin != first.leafPin, notified)
		}
		return ca.Issue(names, key.Public(), now.Add(-time.Hour), now.Add(90*day))
	}
	if got := n.m.Once(ctx, now); got != 2 || notified != 2 || calls != 2 {
		t.Fatalf("stored %d, notified %d, orders %d", got, notified, calls)
	}
}

// A node just updated to cert-pin-v1 gets its first next keys, and with
// them the pins in subscriptions, only from NextKeyFrom on (rayd: ten
// minutes after its start): an update that fails before goes back to a
// version without pins, and none must be with a client by then. Run wakes
// for it. A site's first certificate brings its next key whenever it comes.
func TestManagerNextKeyFrom(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	oldChain, oldKey := operatorCert(t, now.Add(-20*day), now.Add(70*day))
	n.st.SetServiceSecret(ctx, n.id, provision.SecretTLSChain, oldChain)
	n.st.SetServiceSecret(ctx, n.id, provision.SecretTLSKey, pemBytes(t, oldKey))
	n.m.NextKeyFrom = now.Add(10 * time.Minute)
	for _, at := range []time.Time{now, now.Add(10*time.Minute - time.Second)} {
		n.m.Once(ctx, at)
		if s := n.state(); len(s.next) != 0 || s.pins != nil {
			t.Fatalf("a next key %v after the start", at.Sub(now))
		}
	}
	if w := n.m.wait(time.Hour, now); w != 10*time.Minute {
		t.Fatalf("Run sleeps %v, past the time of the first next keys", w)
	}
	n.m.Once(ctx, now.Add(10*time.Minute))
	if s := n.state(); len(s.next) == 0 || s.keys.NextAt != now.Add(10*time.Minute).Unix() || s.keys.NextPin != pinOf(t, s.next) {
		t.Fatalf("no next key ten minutes after the start: %+v", s.keys)
	}
	// A new site in those minutes: its first certificate, its next key.
	n2 := newSiteNode(t, provision.SiteKeyPolicy{})
	n2.m.NextKeyFrom = now.Add(10 * time.Minute)
	if n2.m.Once(ctx, now); len(n2.state().pins) != 2 {
		t.Fatal("a site's first certificate came without its next key")
	}
}

// What the site process would refuse to load is refused before it is
// stored, as a failed issuance: stored, the site kept its old certificate
// until that expired, saying so once in its log, while naive and DoH
// served the new one. Check gets the chain and the key it was ordered for.
func TestManagerCheck(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	short := false
	n.m.Check = func(chainPEM, keyPEM []byte) error {
		if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
			t.Errorf("Check got a chain and a key that do not pair: %v", err)
		}
		if short {
			return errors.New("certificate chain of 1200 bytes, REALITY needs 3622")
		}
		return nil
	}
	var reported error
	n.m.Report = func(_ string, err error) { reported = err }
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("first: stored %d", got)
	}
	first := n.state()
	short = true
	now = now.Add(61 * day)
	if got := n.m.Once(ctx, now); got != 0 || n.m.fails["site"] != 1 || reported == nil || !strings.Contains(reported.Error(), "REALITY needs") {
		t.Fatalf("a chain the site cannot serve: stored %d, failures %d, reported %v", got, n.m.fails["site"], reported)
	}
	if s := n.state(); !bytes.Equal(s.leaf.Raw, first.leaf.Raw) {
		t.Fatal("the refused certificate was stored")
	}
}

// Random walks over what changes the leaf or the pins: time passing with
// renewals, the operator's switches of all three kinds, imports with and
// without force, failing orders. A client that fetched its subscription
// within its 72 hours finds the served leaf in its list, unless since its
// fetch the operator made one of the cuts the commands name: a forced
// switch, a fresh key, an import of another key with force.
func TestManagerInvariantWalk(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 16; seed++ {
		rng := rand.New(rand.NewSource(seed))
		start := time.Now().Truncate(time.Second)
		now := start
		n := newSiteNode(t, provision.SiteKeyPolicy{Period: 180 * day, Lead: 14 * day})
		ca, _ := testCA()
		n.at(ca, &now)
		type fetched struct {
			at   time.Time
			pins []string
			cut  bool // a cut the operator asked for happened since
			how  string
		}
		var subs []*fetched
		var trace []string
		cutAll := func() {
			for _, c := range subs {
				c.cut = true
			}
		}
		fresh, served := false, ""
		step := func(what string) {
			trace = append(trace, fmt.Sprintf("%s +%v", what, now.Sub(start).Round(time.Hour)))
			s := n.state()
			if s.leaf == nil {
				return
			}
			// A fresh key cuts when its certificate is stored, not when it
			// is asked for: the order may fail for days.
			if fresh && s.leafPin != served {
				cutAll()
			}
			fresh = s.keys.RotateAt != 0 && s.keys.RotateHow == provision.SiteSwitchFresh
			served = s.leafPin
			if len(s.pins) > 0 && s.pins[0] != s.leafPin {
				t.Fatalf("seed %d: the first pin is not the leaf's: %v", seed, trace)
			}
			for _, c := range subs {
				if now.Sub(c.at) > 72*time.Hour || len(c.pins) == 0 || c.cut {
					continue
				}
				if !slices.Contains(c.pins, s.leafPin) {
					t.Errorf("seed %d: a client that fetched %v ago (%s) holds %v, the node serves %s\ntrace: %v",
						seed, now.Sub(c.at), c.how, c.pins, s.leafPin, trace)
					c.cut = true
				}
			}
		}
		fetch := func(i int) {
			subs = append(subs, &fetched{at: now, pins: n.state().pins, how: fmt.Sprintf("step %d", i)})
		}
		n.m.Once(ctx, now)
		step("first")
		for i := range 60 {
			switch op := rng.Intn(12); op {
			case 0, 1, 2:
				now = now.Add(time.Duration(1+rng.Intn(30*24)) * time.Hour)
				n.m.Once(ctx, now)
				step("time")
			case 3:
				fetch(i)
				step("fetch")
			case 4:
				err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchLead)
				n.m.Once(ctx, now)
				step(fmt.Sprintf("rotate(%v)", err == nil))
			case 5:
				err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchForce)
				if err == nil {
					cutAll()
				}
				n.m.Once(ctx, now)
				step(fmt.Sprintf("rotate -force(%v)", err == nil))
			case 6:
				force := rng.Intn(2) == 0
				chain, key := operatorCert(t, now.Add(-time.Hour), now.Add(time.Duration(5+rng.Intn(80))*day))
				c, err := provision.SetCertificate(ctx, n.st, "site", chain, key, now, force)
				if err == nil && c.Unpinned {
					cutAll()
				}
				n.m.Once(ctx, now)
				step(fmt.Sprintf("import(force=%v, %v, unpinned=%v)", force, err == nil, c.Unpinned))
			case 7:
				n.fail = !n.fail
				step(fmt.Sprintf("fail=%v", n.fail))
			case 8, 9:
				now = now.Add(time.Duration(1+rng.Intn(48)) * time.Hour)
				n.m.Once(ctx, now)
				fetch(i)
				step("time+fetch")
			case 10:
				// Minutes apart: the hour of the key before, the back-offs.
				now = now.Add(time.Duration(1+rng.Intn(90)) * time.Minute)
				n.m.Once(ctx, now)
				fetch(i)
				step("minutes+fetch")
			case 11:
				if rng.Intn(3) == 0 {
					err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 14*day, provision.SiteSwitchFresh)
					fresh = fresh || err == nil
					n.m.Once(ctx, now)
					step(fmt.Sprintf("rotate -fresh(%v)", err == nil))
				}
			}
		}
	}
}

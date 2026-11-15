package sub_test

import (
	"testing"
)

// A revocation that commits between the subscription's check of the
// device and its reads of the credentials: the revoked device gets no
// subscription, and so not its user's new credentials (R4-36).
func TestRevokeDuringSubscription(t *testing.T) {
	n := newLANNode(t)
	n.user("alice", "hy2", "reality")
	phone := n.device("alice", "phone")
	n.device("alice", "laptop")
	if p, _, code := n.fetch("alice/phone", ""); code != 200 || len(p.Profiles) == 0 {
		t.Fatal(code)
	}
	// Changed runs after the device check and the LAN consent's write,
	// before the subscription is built.
	revoked := false
	n.srv.Changed = func() {
		if _, err := n.st.RevokeDevice(n.ctx, phone.ID); err != nil {
			t.Fatal(err)
		}
		revoked = true
	}
	if p, _, code := n.fetch("alice/phone", "on"); code != 404 || !revoked {
		t.Errorf("revoked during the request: %d, %d profiles (revoked: %v)", code, len(p.Profiles), revoked)
	}
	if _, _, code := n.fetch("alice/phone", ""); code != 404 {
		t.Errorf("after: %d", code)
	}
	if _, _, code := n.fetch("alice/laptop", ""); code != 200 {
		t.Errorf("the user's other device: %d", code)
	}
}

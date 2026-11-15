package main

import (
	"strings"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// relayLines are rayctl update status's lines of the relays in front of
// the node, one each (spec/relay-update-remote-v1.md §9.2): where its
// update by the node's word stands, as rayd has it (§8.2). None from a
// node without relays, or one before them. What rayd says is made
// printable; a state this rayctl does not know is shown as it is.
func relayLines(m *nodev1.GetUpdateStatusResponse) string {
	p := nodeupdate.Printable
	busy := relayBusy(m.Relays)
	var b strings.Builder
	for _, r := range m.Relays {
		name := p(r.Name)
		line := name + ": "
		if r.Version != "" {
			line += p(r.Version) + ", "
		}
		switch r.State {
		case "unknown":
			line += "unknown: no word from it (an older relay, or its rayd relay does not run)"
		case "off":
			line += "off: root on " + name + " has not allowed it (rayctl update remote on there)"
		case "current":
			line += "current"
		case "waiting":
			if busy != "" && busy != r.Name {
				line += "waiting for " + p(busy)
			} else {
				line += "waiting for its turn"
			}
		case "offered":
			line += "offered " + p(r.Target) + relayAt(r.ChangedAt)
		default:
			line += p(r.State)
			if r.Target != "" {
				from := ""
				// The update it follows is the node's last: from what that
				// update came from.
				if s := m.Status; s != nil && r.UpdateId != "" && r.UpdateId == s.Id && s.From != "" {
					from = p(s.From) + " "
				}
				line += " (" + from + "→ " + p(r.Target) + ")"
			}
			line += relayAt(r.ChangedAt)
			switch {
			case r.Reason != "" && r.Error != "":
				line += ", " + p(r.Reason) + ": " + p(r.Error)
			case r.Reason != "" || r.Error != "":
				line += ", " + p(r.Reason+r.Error)
			}
		}
		b.WriteString("relay      " + line + "\n")
	}
	return b.String()
}

// relayBusy is the relay the others wait for (§8.2), "" none: the one
// holding its turn with no word on it yet (offered, which rayd shows only
// then); else the one whose update of the offer the others wait on began
// last (one before it whose turn ran out may still say it updates, until
// an hour of silence fails it); else one still at an earlier update (the
// node updated again meanwhile).
func relayBusy(rs []*nodev1.RelayUpdateStatus) string {
	offer := ""
	for _, r := range rs {
		if r.State == "waiting" && offer == "" {
			offer = r.UpdateId
		}
	}
	busy, rank, at := "", 0, int64(0)
	for _, r := range rs {
		k := 0
		switch {
		case r.State == "offered":
			k = 3
		case r.State != nodeupdate.Requested && r.State != nodeupdate.Running:
			continue
		case offer != "" && r.UpdateId == offer:
			k = 2
		default:
			k = 1
		}
		if k > rank || k == 2 && rank == 2 && r.ChangedAt > at {
			busy, rank, at = r.Name, k, r.ChangedAt
		}
	}
	return busy
}

// relayAt is ", " and the time of unix seconds t, "" for none.
func relayAt(t int64) string {
	if t == 0 {
		return ""
	}
	return ", " + time.Unix(t, 0).UTC().Format(time.RFC3339)
}

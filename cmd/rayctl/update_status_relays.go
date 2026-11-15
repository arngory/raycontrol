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
	// The relay the others wait for: the one the offer went to.
	busy := ""
	for _, r := range m.Relays {
		if busy == "" && (r.State == "offered" || r.State == nodeupdate.Requested || r.State == nodeupdate.Running) {
			busy = r.Name
		}
	}
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

// relayAt is ", " and the time of unix seconds t, "" for none.
func relayAt(t int64) string {
	if t == 0 {
		return ""
	}
	return ", " + time.Unix(t, 0).UTC().Format(time.RFC3339)
}

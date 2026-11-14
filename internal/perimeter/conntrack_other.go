//go:build !linux

package perimeter

// ctnetlink's numbers, as Linux has them (linux/netlink.h,
// linux/netfilter/nfnetlink.h). The perimeter is a node's, and a node is
// Linux: elsewhere the package builds for rayctl, and netlink does not
// dial.
const (
	netlinkNetfilter = 12
	nfnetlinkV0      = 0
)

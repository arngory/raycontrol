package perimeter

import "golang.org/x/sys/unix"

// ctnetlink's numbers (dialConntrack, nfgen).
const (
	netlinkNetfilter = unix.NETLINK_NETFILTER
	nfnetlinkV0      = unix.NFNETLINK_V0
)

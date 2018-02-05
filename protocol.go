package traas2

import "net"

type Probe struct {
	Payload []byte
	MinHop  uint8
	MaxHop  uint8
}

// Hop represents the traceroute at a single TTL
type Hop struct {
	TTL uint8
	IP  net.IP
	Len uint16
}

// Trace represents the stored state for an ongoing traceroute
type Trace struct {
	To       net.IP
	Sent     uint
	Recorded uint16
	Hops     [64]Hop
}

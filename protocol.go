package traas2

import (
	"net"
	"time"
)

// TraceMaxHops indicates how many hops can be recorded for a trace.
const TraceMaxHops = 64

// Probe represents the parameters for sending traceorute packets
type Probe struct {
	Payload []byte
	MinHop  uint8
	MaxHop  uint8
}

// Hop represents the traceroute at a single TTL
type Hop struct {
	TTL      uint8
	IP       net.IP
	Len      uint16
	Received time.Time
}

// Trace represents the stored state for an ongoing traceroute
type Trace struct {
	To       net.IP
	Sent     time.Time
	Recorded uint16
	Hops     [TraceMaxHops]Hop
}

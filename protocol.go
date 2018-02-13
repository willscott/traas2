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
	Received time.Time
}

// Route is a sortable list of hops
type Route []Hop

func (r Route) Len() int           { return len(r) }
func (r Route) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r Route) Less(i, j int) bool { return r[i].TTL < r[j].TTL }

// Trace represents the stored state for an ongoing traceroute
type Trace struct {
	To       net.IP
	Sent     time.Time
	Recorded uint16 `json:"-"`
	Route    Route
	Hops     [TraceMaxHops]Hop `json:"-"`
}

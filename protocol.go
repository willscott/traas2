package traas2

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
)

// TraceMaxReplies indicates how many hops can be recorded for a trace.
const TraceMaxReplies = 64

// TraceShortestTTL indicates the lowest ttl used
const TraceShortestTTL = 4

// TraceLongestTTL indicates the largest ttl used
const TraceLongestTTL = 32

// Probe represents a tcp injection.
type Probe struct {
	Payload []byte
}

// Hop represents the traceroute at a single TTL
type Hop struct {
	TTL      uint8
	IP       net.IP
	Received time.Time
	Packet   gopacket.Packet
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
	Hops     [TraceMaxReplies]Hop `json:"-"`
	Cancel   context.CancelFunc   `json:"-"`
}

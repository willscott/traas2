package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/willscott/traas2"
)

// Recorder is the state of the pcap listener.
// Use begintrace / endTrace to interact with it, and let it know which packets it's watching for.
type Recorder struct {
	handle   *pcap.Handle
	path     string
	parser   *gopacket.DecodingLayerParser
	handlers cmap.ConcurrentMap
	probe    *traas2.Probe
	debug    bool
}

// MakeRecorder initializes the system / pcap listening thread for a given device.
func MakeRecorder(netDev string, path string, port uint16, probe *traas2.Probe, debug bool) (*Recorder, error) {
	handle, err := pcap.OpenLive(netDev, 2048, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	ipv4Layer := new(layers.IPv4)
	ipv4Parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ipv4Layer)

	ief, err := net.InterfaceByName(netDev)
	if err != nil {
		return nil, err
	}
	addrs, err := ief.Addrs()
	if err != nil || len(addrs) == 0 {
		return nil, err
	}

	addrIdx := 0
	for addrs[addrIdx].(*net.IPNet).IP.To4() == nil {
		addrIdx++
		if addrIdx >= len(addrs) {
			return nil, errors.New("no IPv4 Address on Interface")
		}
	}
	src := addrs[addrIdx].(*net.IPNet).IP
	fmt.Printf("Using source of %v\n", src)

	recorder := &Recorder{handle, path, ipv4Parser, cmap.New(), probe, debug}

	//TODO: ICMP?
	fmt.Printf("dst host %s and (icmp or (tcp dst port %d))", src.String(), port)
	err = handle.SetBPFFilter(fmt.Sprintf("dst host %s and (icmp or (tcp dst port %d))", src.String(), port))
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go recorder.watch(packetSource)

	return recorder, nil
}

func (r *Recorder) watch(incoming *gopacket.PacketSource) error {
	for packet := range incoming.Packets() {
		if packet == nil {
			return nil
		}

		//TODO: v6
		ipFrame, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		//icmp
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			if packet.Layer(layers.LayerTypeICMPv4) != nil {
				icmpframe := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				// TODO: should other ICMP codes also be handled?
				if icmpframe.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
					original := gopacket.NewPacket(icmpframe.Payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
					v4 := original.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if v4 != nil {
						if handler, ok := r.handlers.Get(v4.DstIP.String()); ok {
							//fmt.Printf("Matched icmp to handler.\n")
							trace := handler.(*traas2.Trace)

							// see if we got anything interesting in packet options
							for _, opt := range v4.Options {
								if opt.OptionType == 7 {
									log.Printf("route recording got us %x", opt.OptionData)
								} else if opt.OptionType == 4 {
									log.Printf("timestamp got us %x", opt.OptionData)
								}
							}

							if trace.Recorded >= traas2.TraceMaxReplies {
								// trace fully recorded
								continue
							}
							if r.debug {
								log.Printf("Recorded expiry from %s at ttl %d.\n", ipFrame.SrcIP.String(), v4.Id)
								trace.Hops[trace.Recorded].Packet = packet
							}
							trace.Hops[trace.Recorded].IP = ipFrame.SrcIP
							trace.Hops[trace.Recorded].TTL = uint8(v4.Id)
							trace.Hops[trace.Recorded].Received = time.Now()
							trace.Hops[trace.Recorded].Latency = time.Now().Sub(trace.Hops[trace.Recorded].Sent) / 2
							trace.Recorded++
						}
					}
				} else {
					log.Printf("ICMP code %d.%d received from %s.", icmpframe.TypeCode.Type(), icmpframe.TypeCode.Code(), ipFrame.SrcIP)
				}
			}
			continue
		}
		//tcp
		//fmt.Printf("Saw ip packet from %v\n", ipFrame.SrcIP.String())
		if handler, ok := r.handlers.Get(ipFrame.SrcIP.String()); ok {
			trace := handler.(*traas2.Trace)
			if trace.Sent.IsZero() {
				// Make sure this is the request for GET /<path/probe
				tcpFrame := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if tcpFrame == nil {
					continue
				}
				payload := tcpFrame.Payload
				if bytes.IndexByte(payload, 0x0D) == -1 {
					continue
				}
				if !bytes.HasPrefix(payload, []byte("GET ")) ||
					!bytes.Contains(payload[0:bytes.IndexByte(payload, 0x0D)], []byte(r.path+"/probe")) {
					continue
				}

				ctx, cancel := context.WithCancel(context.Background())
				go SpoofProbe(ctx, r.probe, packet, trace, true)

				trace.Cancel = cancel
				trace.Sent = time.Now()
			}
		}
	}
	return nil
}

// Managing traces

// BeginTrace initializes a trace on a specific IP. Triggers sending of 302 probes and recording responses.
func (r *Recorder) BeginTrace(to net.IP) *traas2.Trace {
	t := new(traas2.Trace)
	t.To = to
	r.handlers.Set(to.String(), t)
	return t
}

// GetTrace returns the trace if present for a given IP
func (r *Recorder) GetTrace(to net.IP) *traas2.Trace {
	if val, ok := r.handlers.Get(to.String()); ok {
		return val.(*traas2.Trace)
	}
	return nil
}

// EndTrace cleans up after an active trace.
func (r *Recorder) EndTrace(to net.IP) {
	if val, ok := r.handlers.Get(to.String()); ok {
		tr := val.(*traas2.Trace)
		tr.Cancel()
	}
	r.handlers.Remove(to.String())
}

package server

import (
	"errors"
	"fmt"
	"net"

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
	parser   *gopacket.DecodingLayerParser
	handlers cmap.ConcurrentMap
	probe    *traas2.Probe
}

func MakeRecorder(netDev string, port uint16, probe *traas2.Probe) (*Recorder, error) {
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

	recorder := &Recorder{handle, ipv4Parser, cmap.New(), probe}

	err = handle.SetBPFFilter(fmt.Sprintf("dst host %s and (icmp[0:1] == 0x0b or (tcp dst port %d))", src.String(), port))
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

		ipFrame, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		//icmp
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			//TODO: v6
			if packet.Layer(layers.LayerTypeICMPv4) != nil {
				//fmt.Printf("Received icmp msg\n")
				icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				// TODO: should other ICMP codes also be handled?
				if icmp.TypeCode == layers.ICMPv4CodeTTLExceeded {
					original := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
					v4 := original.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if v4 != nil {
						if handler, ok := r.handlers.Get(v4.DstIP.String()); ok {
							fmt.Printf("Matched icmp to handler.\n")
							trace := handler.(*traas2.Trace)
							trace.Hops[trace.Recorded].IP = ipFrame.SrcIP
							trace.Hops[trace.Recorded].TTL = v4.TTL
							trace.Hops[trace.Recorded].Len = ipFrame.Length
							trace.Recorded++
						}
					}
				}
			}
			continue
		}
		//tcp
		if handler, ok := r.handlers.Get(ipFrame.SrcIP.String()); ok {
			trace := handler.(*traas2.Trace)
			if trace.Sent == 0 {
				tcpFrame := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
				for i := r.probe.MinHop; i < r.probe.MaxHop; i++ {
					SpoofTCPMessage(ipFrame.DstIP, ipFrame.SrcIP, tcpFrame, uint16(len(tcpFrame.Payload)), i, r.probe.Payload)
				}
				trace.Sent = 1
			}
		}
	}
	return nil
}

// Managing traces
func (r *Recorder) BeginTrace(to net.IP) *traas2.Trace {
	t := new(traas2.Trace)
	t.To = to
	r.handlers.Set(to.String(), t)
	return t
}

func (r *Recorder) GetTrace(to net.IP) *traas2.Trace {
	if val, ok := r.handlers.Get(to.String()); ok {
		return val.(*traas2.Trace)
	}
	return nil
}

func (r *Recorder) EndTrace(to net.IP) {
	r.handlers.Remove(to.String())
}

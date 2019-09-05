package server

import (
	"encoding/hex"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/willscott/traas2"

	"log"
	"net"
)

var (
	// TestSpoofChannel can be set, causing spoofed packets to go to it rather than a pcap
	TestSpoofChannel chan []byte
	handle           *pcap.Handle
	ipv4Layer        layers.IPv4
	linkHeader       []byte
)

// SetupSpoofingSockets opens a raw pcap socket for sending packets
func SetupSpoofingSockets(config Config) error {
	var err error

	handle, err = pcap.OpenLive(config.Device, 2048, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	// make sure the handle doesn't queue up packets and start blocking / dying
	handle.SetBPFFilter("ip.len > 5000")

	iface, err := net.InterfaceByName(config.Device)
	if err != nil {
		return err
	}

	dstBytes, _ := hex.DecodeString(config.Dst)
	linkHeader = append(dstBytes, []byte(iface.HardwareAddr)...)
	linkHeader = append(linkHeader, 0x08, 0) // IPv4 EtherType

	//  var ipv6Layer layers.ipv6
	//  ipv6Parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ipv6Layer)
	return nil
}

func getTimestamp() []byte {
	// per http://www.networksorcery.com/enp/protocol/ip/option004.htm
	singleStamp := []byte{0xC4, 0x0C, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	return singleStamp
}

// SpoofTCPMessage constructs and sends a tcp message sent in the same stream as 'request' with a specified payload.
func SpoofTCPMessage(src net.IP, dest net.IP, request *layers.TCP, requestLength uint16, ttl byte, payload []byte) error {
	// Send legit packet.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Id:       uint16(ttl),
		TTL:      ttl,
		Protocol: 6,
		SrcIP:    src,
		DstIP:    dest,
		Flags:    layers.IPv4DontFragment,
		Options: []layers.IPv4Option{layers.IPv4Option{
			OptionType:   7,
			OptionLength: 32,
			OptionData:   make([]byte, 30),
		},
			layers.IPv4Option{
				OptionType:   4,
				OptionLength: 96,
				OptionData:   getTimestamp(),
			}},
	}
	tcp := &layers.TCP{
		SrcPort: request.DstPort,
		DstPort: request.SrcPort,
		Seq:     request.Ack,
		Ack:     request.Seq + uint32(requestLength),
		PSH:     true,
		ACK:     true,
		Window:  122,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	return SpoofIPv4Message(buf.Bytes())
}

// SpoofIPv4Message sends a serialized packet on the raw socket.
func SpoofIPv4Message(packet []byte) error {
	if TestSpoofChannel != nil {
		TestSpoofChannel <- packet
		return nil
	}

	if err := handle.WritePacketData(append(linkHeader, packet...)); err != nil {
		log.Println("Couldn't send packet", err)
		return err
	}
	return nil
}

// SpoofProbe will inject the message specified by probe in repsonse to a given TCP packet.
func SpoofProbe(probe *traas2.Probe, inReplyTo gopacket.Packet, withDelay bool) {
	ipFrame, ok := inReplyTo.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		log.Printf("Asked to spoof but inReply had no ip frame")
		return
	}
	tcpFrame, ok := inReplyTo.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		log.Printf("Asked to spoof but inReply had no tcp frame")
		return
	}

	// probes are sent in pairs of (ttl,ttl+1) with delays to prevent flood triggering
	for i := traas2.TraceShortestTTL; i < traas2.TraceLongestTTL; i++ {
		SpoofTCPMessage(ipFrame.DstIP, ipFrame.SrcIP, tcpFrame, uint16(len(tcpFrame.Payload)), byte(i), probe.Payload)
		SpoofTCPMessage(ipFrame.DstIP, ipFrame.SrcIP, tcpFrame, uint16(len(tcpFrame.Payload)), byte(i+1), probe.Payload)
		if withDelay {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

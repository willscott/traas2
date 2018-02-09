package server

import (
	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"log"
	"net"
)

var (
	// If TestChannel is set, spoofed packets will be sent to it, rather than to pcap.
	TestSpoofChannel chan []byte
	handle           *pcap.Handle
	ipv4Layer        layers.IPv4
	linkHeader       []byte
)
var ipv4Parser *gopacket.DecodingLayerParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4Layer)

func SetupSpoofingSockets(config Config) error {
	var err error

	handle, err = pcap.OpenLive(config.Device, 2048, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	// make sure the handle doesn't queue up packets and start blocking / dying
	handle.SetBPFFilter("ip.len > 5000")

	srcBytes, _ := hex.DecodeString(config.Src)
	dstBytes, _ := hex.DecodeString(config.Dst)
	linkHeader = append(dstBytes, srcBytes...)
	linkHeader = append(linkHeader, 0x08, 0) // IPv4 EtherType

	//  var ipv6Layer layers.ipv6
	//  ipv6Parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ipv6Layer)
	return nil
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

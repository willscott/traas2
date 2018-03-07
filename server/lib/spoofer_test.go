package server

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/willscott/traas2"
)

func TestProbe(t *testing.T) {
	// Send packets to channel, rather than socket.
	TestSpoofChannel = make(chan []byte, (traas2.TraceLongestTTL-traas2.TraceShortestTTL)*2)

	host := net.ParseIP("127.0.0.1")

	// Send legit packet.
	payload := "hello world"
	tcp := &layers.TCP{
		Ack:     1024,
		Seq:     512,
		ACK:     true,
		DstPort: 80,
		SrcPort: 8080,
	}

	err := SpoofTCPMessage(host, host, tcp, 512, 64, []byte(payload))
	if err != nil {
		t.Fatalf("Failed to spoof msg: %v", err)
	}
	sentPkt := <-TestSpoofChannel
	if !bytes.Contains(sentPkt, []byte(payload)) {
		t.Fatal("Valid packet not spoofed")
	}

	ip := &layers.IPv4{
		Version:  4,
		Protocol: 6,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
		Flags:    layers.IPv4DontFragment,
	}
	serializer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(serializer, gopacket.SerializeOptions{FixLengths: true}, ip, tcp)
	pkt := gopacket.NewPacket(serializer.Bytes(), layers.LayerTypeIPv4, gopacket.DecodeOptions{})
	SpoofProbe(&traas2.Probe{Payload: []byte(payload)}, pkt, false)

	// Non-blocking read of the channel to see if an immediate packet was sent.
	select {
	case firstSend := <-TestSpoofChannel:
		if !bytes.Contains(firstSend, []byte(payload)) {
			t.Fatal("Valid packet not spoofed")
		}
	default:
		t.Fatal("Some packet should be sent immediately from spoofprobe.")
	}
}

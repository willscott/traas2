package server

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestProbe(t *testing.T) {
	// Send packets to channel, rather than socket.
	TestSpoofChannel = make(chan []byte, 5)

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
}

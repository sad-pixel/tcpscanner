package sniffer

import (
	"net"

	"github.com/google/gopacket/layers"
)

// TrackedPacket stores the packet details that are relevant
// to our use case
type TrackedPacket struct {
	SrcPort, DstPort layers.TCPPort
	SrcIP, DstIP     net.IP
	PacketType       string

	GeoCountry string
	GeoISP     string
}

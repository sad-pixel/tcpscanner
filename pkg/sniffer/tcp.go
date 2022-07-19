package sniffer

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetIsTCP checks if the given packet has a TCP layer
func packetIsTCP(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeTCP) != nil
}

// packetIsIPv4 checks if the given packet has a IPv4 layer
func packetIsIPv4(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeIPv4) != nil
}

// packetIsIPv6 checks if the given packet has a IPv6 layer
func packetIsIPv6(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeIPv6) != nil
}

// getSynOrFin checks if the given TCP packet is of type SYN, FIN or neither
func getSynOrFin(tcpPacket *layers.TCP) (string, bool) {
	if tcpPacket.SYN {
		return "SYN", true
	}

	if tcpPacket.FIN {
		return "FIN", true
	}

	return "", false
}

// extractPacketData takes a raw packet, and extracts the relevant data for
// our use case into a *TrackedPacket
func extractPacketData(packet gopacket.Packet) (*TrackedPacket, error) {
	tp := &TrackedPacket{}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcpData, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil, errors.New("could not decode tcp layer")
	}

	tp.SrcPort = tcpData.SrcPort
	tp.DstPort = tcpData.DstPort
	tp.PacketType, _ = getSynOrFin(tcpData)

	if packetIsIPv4(packet) {
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		ipv4Data, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return nil, errors.New("could not decode ipv4 layer")
		}

		tp.SrcIP = ipv4Data.SrcIP
		tp.DstIP = ipv4Data.DstIP
	}

	if packetIsIPv6(packet) {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		ipv6Data, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return nil, errors.New("could not decode ipv6 layer")
		}

		tp.SrcIP = ipv6Data.SrcIP
		tp.DstIP = ipv6Data.DstIP
	}

	return tp, nil
}

// shouldStorePacket takes a *TrackedPacket and returns true if it satisfies the
// filters relevant to our use case (either destination or source port is 80 AND
// the packet is of type either SYN or FIN)
func shouldStorePacket(packet *TrackedPacket) bool {
	if packet.DstPort != 80 && packet.SrcPort != 80 {
		return false
	}

	if packet.PacketType == "" {
		return false
	}

	return true
}

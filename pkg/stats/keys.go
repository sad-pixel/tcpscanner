package stats

import (
	"fmt"
	"strings"

	"github.com/sad-pixel/tcpscanner/pkg/sniffer"
)

// getPacketKey encodes a *sniffer.TrackedPacket into a string so it can be used
// as a map key
func getPacketKey(packet *sniffer.TrackedPacket) string {
	return strings.Join([]string{
		packet.SrcIP.String(),
		packet.DstIP.String(),
		packet.PacketType,
	}, "#")
}

// decodeKey decodes a key encoded by getPacketKey into a slice of strings with the
// source IP, destination IP, and packet type
func decodeKey(key string) ([]string, error) {
	fields := strings.FieldsFunc(key, func(r rune) bool {
		return r == '#'
	})

	if len(fields) != 3 {
		return nil, fmt.Errorf("could not decode packet store key: expected 3 fields, found %d instead", len(fields))
	}

	return fields, nil
}

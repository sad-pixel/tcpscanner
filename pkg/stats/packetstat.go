package stats

import "fmt"

// PacketStat represents the final aggregate statistics
type PacketStat struct {
	DstIP      string
	PacketType string

	SrcIP  string
	SrcGeo string
	SrcISP string

	Count uint64
}

func (s *PacketStat) String() string {
	return fmt.Sprintf("SRC: %s, DST: %s, TYPE: %s, C: %d", s.SrcIP, s.DstIP, s.PacketType, s.Count)
}

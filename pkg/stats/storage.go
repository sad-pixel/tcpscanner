package stats

import (
	"sync"

	"github.com/sad-pixel/tcpscanner/pkg/sniffer"
)

// CountStore stores aggregated packet counts
type CountStore struct {
	counts map[string]uint64
	mu     sync.Mutex
}

// NewCountStore creates a new *CountStore
func NewCountStore() *CountStore {
	var c CountStore
	c.counts = make(map[string]uint64)

	return &c
}

// StorePacket takes a *sniffer.TrackedPacket, and increments the relevant
// aggegate counter
func (store *CountStore) StorePacket(packet *sniffer.TrackedPacket) {
	store.mu.Lock()
	store.counts[getPacketKey(packet)]++
	store.mu.Unlock()
}

// GenerateStats creates a slice of []PacketStat by decoding the map keys
// and inserting the counts
func (store *CountStore) GenerateStats() ([]PacketStat, error) {
	store.mu.Lock()
	counts := store.counts
	store.counts = make(map[string]uint64)
	store.mu.Unlock()

	stats := []PacketStat{}

	for key, count := range counts {
		keyData, err := decodeKey(key)
		if err != nil {
			return nil, err
		}

		stat := PacketStat{}
		stat.SrcIP = keyData[0]
		stat.DstIP = keyData[1]
		stat.PacketType = keyData[2]
		stat.Count = count

		stats = append(stats, stat)
	}

	return stats, nil
}

package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// CapturePackets creates a pcap handle and captures all packets arriving
func CapturePackets(device string, snapLen int32, isPromiscuous bool, timeout time.Duration, sendChan chan<- *TrackedPacket) error {
	captureHandle, err := pcap.OpenLive(device, snapLen, isPromiscuous, timeout)
	if err != nil {
		return fmt.Errorf("could not open pcap handle: %w", err)
	}
	defer captureHandle.Close()

	source := gopacket.NewPacketSource(captureHandle, captureHandle.LinkType())

	for packet := range source.Packets() {
		if packetIsTCP(packet) {
			p, err := extractPacketData(packet)
			if err != nil {
				log.Println("could not extract packet data: " + err.Error())
			}
			if shouldStorePacket(p) {
				sendChan <- p
			}
		}
	}

	return nil
}

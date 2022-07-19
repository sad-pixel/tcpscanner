package sniffer

import (
	"log"

	"github.com/google/gopacket/pcap"
)

// PrintDevicesList is a utility function that prints the list of connected
// network devices
func PrintDevicesList() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Could not fetch devices: %v\n", err.Error())
	}

	log.Printf("List of connected devices:")

	for i, device := range devices {
		log.Printf("Dev #%d: %s", i, device.Name)
	}
}

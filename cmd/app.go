package cmd

import (
	"encoding/csv"
	"log"
	"net"
	"time"

	"github.com/sad-pixel/tcpscanner/pkg/geo"
	"github.com/sad-pixel/tcpscanner/pkg/report"
	"github.com/sad-pixel/tcpscanner/pkg/sniffer"
	"github.com/sad-pixel/tcpscanner/pkg/stats"
	"github.com/urfave/cli/v2"
)

func SniffPackets(ctx *cli.Context) error {
	log.Println("TCP Scanner started")
	log.Println("Press CTRL-C to exit")

	captureInterface := ctx.String("iface")
	outFile := ctx.String("outfile")
	isPromiscuous := ctx.Bool("promiscuous")

	sniffedPacketsChan := make(chan *sniffer.TrackedPacket)
	counts := stats.NewCountStore()
	ticker := time.NewTicker(5 * time.Minute)

	// This goroutine sniffs the packets
	go func() {
		if err := sniffer.CapturePackets(captureInterface, 65535, isPromiscuous, -1*time.Second, sniffedPacketsChan); err != nil {
			log.Fatalln(err.Error())
		}
	}()

	// This goroutine takes sniffed packets and sends them for aggregation
	go func(inChan <-chan *sniffer.TrackedPacket, countStore *stats.CountStore) {
		for packet := range inChan {
			countStore.StorePacket(packet)
		}
	}(sniffedPacketsChan, counts)

	geoHandler := geo.GeoIpHandler{}
	err := geoHandler.LoadGeoIPDatabases("./geoip/country.mmdb", "./geoip/asn.mmdb")
	if err != nil {
		log.Fatalln("could not load geoip databases: " + err.Error())
	}
	defer geoHandler.CloseDatabases()

	csvFile, err := report.GetFileHandle(outFile)
	if err != nil {
		log.Fatalln("could not load csv file: " + err.Error())
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)

	for range ticker.C {
		st, err := counts.GenerateStats()
		if err != nil {
			log.Println("could not generate stats: " + err.Error())
		}

		if len(st) == 0 {
			continue
		}

		log.Printf("writing %d records to CSV\n", len(st))

		statsWithGeo := []stats.PacketStat{}
		for _, s := range st {
			srcIp := net.ParseIP(s.SrcIP)
			geoResult, err := geoHandler.LookupIP(srcIp)
			if err != nil {
				log.Printf("geolookup for ip %s failed: %s\n", srcIp, err.Error())
			}

			s.SrcGeo = geoResult.Country
			s.SrcISP = geoResult.Isp

			statsWithGeo = append(statsWithGeo, s)
		}

		err = report.WriteStatToCSV(csvWriter, statsWithGeo)
		if err != nil {
			log.Printf("error writing stats to CSV: %s\n", err.Error())
		}
	}

	return nil
}

package main

import (
	"log"
	"os"

	"github.com/sad-pixel/tcpscanner/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "tcpscanner",
		Usage: "scans TCP port 80 for packets and generates CSV report",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "show a list of connected network devices",
				Action: cmd.ListDevices,
			},
			{
				Name:   "scan",
				Usage:  "runs the tcp sniffer",
				Action: cmd.SniffPackets,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "iface",
						Aliases:  []string{"i"},
						Usage:    "the network interface or device to listen on",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "outfile",
						Aliases: []string{"o"},
						Value:   "report.csv",
						Usage:   "the path of the output CSV file",
					},
					&cli.BoolFlag{
						Name:    "promiscuous",
						Aliases: []string{"p"},
						Usage:   "enable promiscuous mode",
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

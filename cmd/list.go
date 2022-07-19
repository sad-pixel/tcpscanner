package cmd

import (
	"github.com/sad-pixel/tcpscanner/pkg/sniffer"
	"github.com/urfave/cli/v2"
)

func ListDevices(*cli.Context) error {
	sniffer.PrintDevicesList()
	return nil
}

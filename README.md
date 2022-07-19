# TCP Scanner

Scans TCP port 80 incoming and outgoing for SYN/FIN packets, and writes aggregated statistics about the scanned packets.

# Prerequisites
This project requires CGO, please make sure you have the appropriate tools installed. 

Before building, make sure the `pcap` headers are installed
```
$ sudo apt-get install libpcap0.8-dev
```

This project also requires MaxMind's GeoIP-Lite databases for country and ASN. Place them in the `geoip` folder, with the names:
- `asn.mmdb` for the ASN database
- `country.mmdb` for the Country database

The databases can be obtained from [here](https://www.maxmind.com/en/geolite2)

# Usage
Run the binary without any arguments to see the help menu
```
NAME:
   tcpscanner - scans TCP port 80 for packets and generates CSV report

USAGE:
   tcpscanner [global options] command [command options] [arguments...]

COMMANDS:
   list     show a list of connected network devices
   scan     runs the tcp sniffer
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```

## See List of Connected Devices/Interfaces

Use `list` subcommand to see the list of connected network devices/interfaces. You will need to pass one to the `scan` command.


```
$ ./tcpscanner list
2022/07/17 07:10:37 List of connected devices:
2022/07/17 07:10:37 Dev #0: wlp3s0
2022/07/17 07:10:37 Dev #1: veth4fdd6a9
2022/07/17 07:10:37 Dev #2: br-533b2af2c47e
2022/07/17 07:10:37 Dev #3: veth8e76255
2022/07/17 07:10:37 Dev #4: lo
2022/07/17 07:10:37 Dev #5: any
2022/07/17 07:10:37 Dev #6: br-ea48116ae7fe
2022/07/17 07:10:37 Dev #7: docker0
2022/07/17 07:10:37 Dev #8: eno1
2022/07/17 07:10:37 Dev #9: br-96b9e5ebac79
2022/07/17 07:10:37 Dev #10: bluetooth-monitor
2022/07/17 07:10:37 Dev #11: nflog
2022/07/17 07:10:37 Dev #12: nfqueue
2022/07/17 07:10:37 Dev #13: bluetooth0
```

## Running the scanner
This command should be run as the `root` user.
```
USAGE:
   tcpscanner scan [command options] [arguments...]

OPTIONS:
   --iface value, -i value    the network interface or device to listen on
   --outfile value, -o value  the path of the output CSV file (default: "report.csv")
   --promiscuous, -p          enable promiscuous mode (default: false)
```

Ex. 1 (fails because user does not have sufficient permission to listen on the interface):
```
$ ./tcpscanner scan -i wlp3s0
2022/07/17 07:14:07 TCP Scanner started
2022/07/17 07:14:07 Press CTRL-C to exit
2022/07/17 07:14:07 could not open pcap handle: wlp3s0: You don't have permission to capture on that device (socket: Operation not permitted)
```

Ex. 2:
```
$ sudo ./tcpscanner scan -i wlp3s0
2022/07/19 07:15:05 TCP Scanner started
2022/07/19 07:15:05 Press CTRL-C to exit
2022/07/19 07:20:05 writing 2 records to CSV
2022/07/19 07:25:05 writing 2 records to CSV
2022/07/19 07:30:05 writing 1 records to CSV
2022/07/19 07:35:05 writing 2 records to CSV
2022/07/19 07:40:05 writing 2 records to CSV
2022/07/19 07:15:05 writing 1 records to CSV
```


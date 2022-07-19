package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoHandler stores the geoip databases in memory
type GeoIpHandler struct {
	countries, isps *geoip2.Reader
}

// GeoIpResult stores the result of the GeoIp country and ISP lookup
type GeoIpResult struct {
	Country string
	Isp     string
}

// LoadGeoIPDatabases loads the provided country and ASN databases into
// the handler
func (h *GeoIpHandler) LoadGeoIPDatabases(countryPath, ispPath string) error {
	countries, err := geoip2.Open(countryPath)
	if err != nil {
		return fmt.Errorf("could not open countries database: %w", err)
	}

	isps, err := geoip2.Open(ispPath)
	if err != nil {
		return fmt.Errorf("could not open isp database: %w", err)
	}

	h.countries = countries
	h.isps = isps
	return nil
}

// CloseDatabases closes the GeoIP database readers
func (h *GeoIpHandler) CloseDatabases() {
	h.countries.Close()
	h.isps.Close()
}

// LookupIP takes a net.IP and returns a GeoIpResult with the country
// and ISP details or an error
func (h *GeoIpHandler) LookupIP(ip net.IP) (GeoIpResult, error) {
	res := GeoIpResult{}

	countryRecord, err := h.countries.Country(ip)
	if err != nil {
		return res, fmt.Errorf("could not get country: %w", err)
	}

	ispRecord, err := h.isps.ASN(ip)
	if err != nil {
		return res, fmt.Errorf("could not get isp: %w", err)
	}

	res.Country = countryRecord.Country.Names["en"]

	if ispRecord.AutonomousSystemNumber != 0 {
		res.Isp = fmt.Sprintf("%d - %s", ispRecord.AutonomousSystemNumber, ispRecord.AutonomousSystemOrganization)
	}

	return res, nil
}

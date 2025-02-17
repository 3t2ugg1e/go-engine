package geoip

import (
	"errors"
	"github.com/3t2ugg1e/go-engine/src/common"
	"net"
)

var gdb *geoip2.Reader

func Load(file string) error {

	if len(file) <= 0 {
		file = common.GetDataDir() + "/geoip/" + "GeoLite2-Country.mmdb"
	}

	db, err := geoip2.Open(file)
	if err != nil {
		return err
	}
	gdb = db
	return nil
}

func GetCountryIsoCode(ipaddr string) (string, error) {

	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return "", errors.New("ip " + ipaddr + " ParseIP nil")
	}
	record, err := gdb.City(ip)
	if err != nil {
		return "", err
	}

	return record.Country.IsoCode, nil
}

func GetCountryName(ipaddr string) (string, error) {

	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return "", errors.New("ip " + ipaddr + "ParseIP nil")
	}
	record, err := gdb.City(ip)
	if err != nil {
		return "", err
	}

	return record.Country.Names["en"], nil
}

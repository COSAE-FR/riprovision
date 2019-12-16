package base

import (
	"github.com/gcrahay/riprovision/arp"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)


func (h *Server) validPrefix(mac string) bool {
	if len(h.MACPrefix) == 0 {
		return true
	}
	for _, prefix := range h.MACPrefix {
		if strings.HasPrefix(mac, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func (h *Server) ValidMAC(mac string) bool {
	mac = strings.ToLower(mac)
	logger := h.Log.WithFields(log.Fields{
		"device": mac,
		"component": "mac_validator",
	})
	if !h.validPrefix(mac) {
		logger.Error("Invalid prefix")
		return false
	}
	macEntries := arp.ReverseSearch(mac)
	for _, macEntry := range macEntries {
		if macEntry.Permanent != true {
			logger.Infof("Non permanent MAC entry on interface: %s", macEntry.Iface)
			continue
		}
		if !stringInSlice(macEntry.Iface, h.Provision.InterfaceNames) {
			logger.Infof("Not a provisioning interface: %s", macEntry.Iface)
			continue
		}
		netInterface, err := net.InterfaceByName(macEntry.Iface)
		if err == nil {
			addresses, err := netInterface.Addrs()
			if err == nil {
				for _, a := range addresses {
					switch v := a.(type) {
					case *net.IPNet:
						if v.IP.To4() != nil {
							break
						}
					default:
						logger.Infof("Cannot guess interface address on interface: %s", macEntry.Iface)
						continue
					}
				}
			} else {
				logger.Infof("Cannot find addresses for interfaces: %s", macEntry.Iface)
				continue
			}
		} else {
			logger.Infof("Cannot find interface %s on server", macEntry.Iface)
			continue
		}
		return true
	}
	return false
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

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
	if !h.validPrefix(mac) {
		log.Warnf("[Client %s] Invalid prefix", mac)
	}
	macEntries := arp.ReverseSearch(mac)
	for _, macEntry := range macEntries {
		if macEntry.Permanent != true {
			log.Warnf("[Client %s] Non permanent MAC entry, searching: %+v", mac, macEntry)
			continue
		}
		if !stringInSlice(macEntry.Iface, h.Provision.InterfaceNames) {
			log.Warnf("[Client %s] Not a client interface, searching: %+v", mac, macEntry)
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
						log.Debugf("[Client %s] Cannot guess interface address, searching: %+v", mac, macEntry)
						continue
					}
				}
			} else {
				log.Debugf("[Client %s] Cannot find interface addresses, searching: %+v", mac, macEntry)
				continue
			}
		} else {
			log.Debugf("[Client %s] Cannot find interface on server, searching: %+v", mac, macEntry)
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

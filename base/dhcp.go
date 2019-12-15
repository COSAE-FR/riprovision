package base

import (
	"github.com/gcrahay/riprovision/address"
	"github.com/gcrahay/riprovision/arp"
	"github.com/gcrahay/riprovision/network"
	"github.com/krolaw/dhcp4"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
	"time"
)

func (h *Server) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) (d dhcp4.Packet) {

	mac := p.CHAddr().String()
	logger := log.WithField("device", mac)
	logger.Debugf("DHCP handler: Got packer from %s", mac)
	if !h.validMAC(mac) {
		logger.Error("Unauthorized client")
		return nil
	}

	device, found := h.GetDevice(mac)
	if !found {
		logger.Debugf("DHCP handler: Device not found, creating")
		deviceLogger := log.WithField("device", mac)
		device = Device{
			MacAddress: mac,
			Unifi:      nil,
			DHCP:       nil,
			Log:        deviceLogger,
		}
	}
	if device.DHCP == nil || device.DHCP.ClientIP == nil || time.Now().After(device.DHCP.Expiry) {
		device.Log.Debug("DHCP handler: no DHCP informations")
		freeNetwork, err := h.GetDHCPNetwork()
		if err != nil {
			device.Log.Printf("No free network")
			return
		}
		device.Log.Debugf("DHCP handler: asking for address creation: %s", freeNetwork.String())
		//h.AddNet <- *freeNetwork
		h.ManageNet <- address.InterfaceAddress{
			Network:   *freeNetwork,
			Interface: h.Interface,
		}
		_, targetNetwork, err := net.ParseCIDR(freeNetwork.String())
		if err != nil {
			device.Log.Errorf("Cannot get server IP: %v", err)
			return
		}
		serverIP := network.NextIP(targetNetwork.IP, 1)
		clientIP := network.NextIP(targetNetwork.IP, 2)
		device.DHCP = &DHCPDevice{
			ServerIP:    &serverIP,
			NetworkMask: &freeNetwork.Mask,
			ClientIP:    &clientIP,
			Expiry:      time.Now().Add(h.DHCP.leaseDuration),
		}

	} else {
		device.DHCP.Expiry = time.Now().Add(h.DHCP.leaseDuration)
	}
	h.AddDevice(device)
	serverOptions := dhcp4.Options{
		dhcp4.OptionSubnetMask:       *device.DHCP.NetworkMask,
		dhcp4.OptionRouter:           device.DHCP.ServerIP.To4(), // Presuming Server is also your router
		dhcp4.OptionDomainNameServer: device.DHCP.ServerIP.To4(), //
	}
	switch msgType {

	case dhcp4.Discover:
		return dhcp4.ReplyPacket(p, dhcp4.Offer, *device.DHCP.ServerIP, *device.DHCP.ClientIP, h.DHCP.leaseDuration,
			serverOptions.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))

	case dhcp4.Request:
		reqIP := net.IP(options[dhcp4.OptionRequestedIPAddress])
		if reqIP == nil {
			reqIP = net.IP(p.CIAddr())
		}

		if len(reqIP) == 4 && !reqIP.Equal(net.IPv4zero) {
			return dhcp4.ReplyPacket(p, dhcp4.ACK, *device.DHCP.ServerIP, reqIP, h.DHCP.leaseDuration,
				serverOptions.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))

		}
		return dhcp4.ReplyPacket(p, dhcp4.NAK, *device.DHCP.ServerIP, nil, 0, nil)

	case dhcp4.Release, dhcp4.Decline:
		device.Log.Debugf("DHCP request is %v", msgType)
	default:
		device.Log.Debugf("DHCP request was %v. NOOP.", msgType)

	}
	device.Log.Debugf("Cannot handle this DHCP request")
	return nil
}

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

func (h *Server) validMAC(mac string) bool {
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

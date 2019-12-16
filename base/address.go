package base

import (
	"github.com/gcrahay/riprovision/address"
	"github.com/gcrahay/riprovision/network"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func (server *Server) GetDHCPNetwork() (*net.IPNet, error) {
	var networks []net.IPNet
	for _, deviceMAC := range server.Cache.Keys() {
		device, found := server.GetDevice(deviceMAC.(string))
		if found && device.DHCP.ServerIP != nil {
			deviceNetwork := net.IPNet{
				IP:   device.DHCP.ServerIP.Mask(*device.DHCP.NetworkMask),
				Mask: *device.DHCP.NetworkMask,
			}
			networks = append(networks, deviceNetwork)
		}
	}
	server.Log.WithField("component", "network_finder").Debugf("Used networks computed (%d)", len(networks))
	return network.GetFreeNetworkBlacklist(server.DHCP.baseNetwork, server.DHCP.NetworkPrefix, networks)
}

func LocalAddressManager(addressChan chan address.InterfaceAddress, exit chan int) {
	log.Debugf("interface IP address manager started")
	for {
		select {
		case <-exit:
			log.Info("interface IP address manager exit requested")
			return
		case ipNetwork := <-addressChan:
			log.Debugf("NewHandler address to add: %s", ipNetwork.Network.String())
			_, targetNetwork, err := net.ParseCIDR(ipNetwork.Network.String())
			if err != nil {
				log.Errorf("Cannot get server IP: %+v", err)
				continue
			}
			serverIP := network.NextIP(targetNetwork.IP, 1)
			if ipNetwork.Remove {
				err = address.RemoveInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
				if err != nil {
					log.Errorf("Cannot remove server IP: %v", err)
				}
				continue
			} else {
				err = address.AddInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
				if err != nil {
					log.Errorf("Cannot add server IP: %v", err)
				}
				continue
			}
		}
	}
}

func (server *Server) LocalAddressCLeaner() {
	logger := server.Log.WithFields(log.Fields{
		"component": "address_cleaner",
	})
	logger.Debugf("interface IP address cleaner started")
	for {
		select {
		case <-server.StopClean:
			logger.Info("Interface IP address cleaner exit requested")
			return
		case <- server.CleanTicker.C:
			now := time.Now()
			logger.Debugf("Cleaner started at %s", now.String())
			for _, deviceKeyInt := range server.Cache.Keys() {
				device, found := server.GetDevice(deviceKeyInt.(string))
				if found {
					if device.DHCP != nil && device.DHCP.ServerIP != nil && now.After(device.DHCP.Expiry) {
						logger.Debugf("Removing expired network for server: %s", device.DHCP.ServerIP.String())

						server.ManageNet <- address.InterfaceAddress{
							Network:   net.IPNet{IP: *device.DHCP.ServerIP, Mask: *device.DHCP.NetworkMask},
							Interface: server.Interface,
							Remove:    true,
						}
						device.DHCP = nil
						server.AddDevice(device)
					}
				}
			}
		}
	}
}


func (server *Server) RemoteAddressManager(address chan address.InterfaceAddress, exit chan int) {
	log.Debugf("interface IP address manager started")
	for {
		select {
		case <-exit:
			log.Info("interface IP address manager exit requested")
			return
		case ipNetwork := <-address:
			log.Debugf("NewHandler address to add: %s", ipNetwork.Network.String())
			msg, err := server.NetManager.Manage(&ipNetwork)
			if err != nil {
				log.Errorf("Cannot manager server IP: %v (%s)", err, msg)
			} else {
				log.Debugf("Server IP managed: %s", msg)
			}
			continue
		}
	}
}
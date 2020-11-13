package base

import (
	"github.com/COSAE-FR/riprovision/address"
	"github.com/COSAE-FR/riprovision/network"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func (server *Server) GetDHCPNetwork() (*net.IPNet, error) {
	var networks []net.IPNet
	for _, deviceMAC := range server.Cache.Keys() {
		device, found := server.GetDevice(deviceMAC.(string))
		if found && device.DHCP != nil && device.DHCP.ServerIP != nil && device.DHCP.NetworkMask != nil {
			deviceNetwork := net.IPNet{
				IP:   device.DHCP.ServerIP.Mask(*device.DHCP.NetworkMask),
				Mask: *device.DHCP.NetworkMask,
			}
			if deviceNetwork.IP == nil {
				server.Log.WithField("component", "network_finder").Warn("Cannot get server IP network")
				continue
			}
			server.Log.WithField("component", "network_finder").Tracef("Found IP network: %s", deviceNetwork.String())
			networks = append(networks, deviceNetwork)
		}
	}
	server.Log.WithField("component", "network_finder").Debugf("Used networks computed (%d)", len(networks))
	return network.GetFreeNetworkBlacklist(server.DHCP.baseNetwork, server.DHCP.NetworkPrefix, networks)
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
		case <-server.CleanTicker.C:
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
	logger := server.Log.WithField("component", "address_manager")
	logger.Debugf("interface IP address manager started")
	for {
		select {
		case <-exit:
			logger.Info("interface IP address manager exit requested")
			return
		case ipNetwork := <-address:
			logger.Debugf("Received address to add: %s", ipNetwork.Network.String())
			msg, err := server.NetManager.Manage(&ipNetwork)
			if err != nil {
				logger.Errorf("Cannot manager server IP: %v (%s)", err, msg)
			} else {
				logger.Debugf("Interface address set/unset: %s", msg)
			}
			continue
		}
	}
}

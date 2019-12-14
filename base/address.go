package base

import (
	"fmt"
	"github.com/gcrahay/riprovision/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

type ComContext struct {
	handler  *PacketHandler
	network  *net.IPNet
	clientIP *net.IP
	expiry   time.Time
}

func NewContext(base *net.IPNet, prefix int) (*ComContext, error) {
	var err error
	ctx := &ComContext{expiry: time.Now().Add(10 * time.Minute)}
	ctx.network, err = network.GetFreeNetwork(base, prefix)
	if err != nil {
		return ctx, err
	}
	return ctx, nil
}

type Connection struct {
	in        chan gopacket.Packet
	out       chan *gopacket.Packet
	layerType gopacket.LayerType
}

func (c *Connection) ReadFrom(b []byte) (n int, sourceAddr net.Addr, err error) {
	packet := <-c.in
	udpLayer := packet.Layer(c.layerType)
	if udpLayer == nil {
		return c.ReadFrom(b)
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	b = udpLayer.LayerContents()
	source := fmt.Sprintf("%s:%s", ipLayer.(*layers.IPv4).SrcIP.String(), udpLayer.(*layers.UDP).SrcPort.String())
	addr, err := net.ResolveUDPAddr("udp4", source)
	return len(b), addr, err
}

type DHCPContext struct {
}

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
	log.Debugf("Used networks computed (%d)", len(networks))
	return network.GetFreeNetworkBlacklist(server.DHCP.baseNetwork, server.DHCP.NetworkPrefix, networks)
}

type InterfaceAddress struct {
	Network net.IPNet
	Interface string
	Remove bool
}

func LocalAddressManager(address chan InterfaceAddress, exit chan int) {
	log.Debugf("interface IP address manager started")
	for {
		select {
		case <-exit:
			log.Info("interface IP address manager exit requested")
			return
		case ipNetwork := <-address:
			log.Debugf("New address to add: %s", ipNetwork.Network.String())
			_, targetNetwork, err := net.ParseCIDR(ipNetwork.Network.String())
			if err != nil {
				log.Errorf("Cannot get server IP: %+v", err)
				continue
			}
			serverIP := network.NextIP(targetNetwork.IP, 1)
			if ipNetwork.Remove {
				err = RemoveInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
				if err != nil {
					log.Errorf("Cannot remove server IP: %v", err)
				}
				continue
			} else {
				err = AddInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
				if err != nil {
					log.Errorf("Cannot add server IP: %v", err)
				}
				continue
			}
		}
	}
}

func (server *Server) LocalAddressManager(add chan net.IPNet, remove chan net.IPNet, exit chan int) {
	log.Debugf("interface IP address manager started")
	for {
		select {
		case <-exit:
			log.Info("interface IP address manager exit requested")
			return
		case ipNetwork := <-add:
			log.Debugf("New address to add: %s", ipNetwork.String())
			_, targetNetwork, err := net.ParseCIDR(ipNetwork.String())
			if err != nil {
				log.Errorf("Cannot get server IP: %+v", err)
				continue
			}
			serverIP := network.NextIP(targetNetwork.IP, 1)
			err = AddInterfaceIP(serverIP, ipNetwork.Mask, server.Interface)
			if err != nil {
				log.Errorf("Cannot add server IP: %v", err)
				continue
			}
			continue
		case ipNetwork := <-remove:
			log.Debugf("New address to remove: %s", ipNetwork.String())
			_, targetNetwork, err := net.ParseCIDR(ipNetwork.String())
			if err != nil {
				log.Errorf("Cannot get server IP: %v", err)
				continue
			}
			serverIP := network.NextIP(targetNetwork.IP, 1)
			err = RemoveInterfaceIP(serverIP, ipNetwork.Mask, server.Interface)
			if err != nil {
				log.Errorf("Cannot remove server IP: %v", err)
				continue
			}
			continue
		}
	}
}

func (server *Server) LocalAddressCLeaner() {
	log.Debugf("interface IP address cleaner started")
	for {
		select {
		case <-server.StopClean:
			log.Info("Interface IP address cleaner exit requested")
			return
		case <- server.CleanTicker.C:
			now := time.Now()
			log.Debugf("Cleaner started at %s", now.String())
			for _, deviceKeyInt := range server.Cache.Keys() {
				device, found := server.GetDevice(deviceKeyInt.(string))
				if found {
					if device.DHCP != nil && device.DHCP.ServerIP != nil && now.After(device.DHCP.Expiry) {
						log.Debugf("Cleaner: removing expired network for server: %s", device.DHCP.ServerIP.String())
						//server.RemoveNet <- net.IPNet{IP: *device.DHCP.ServerIP, Mask: *device.DHCP.NetworkMask}
						server.ManageNet <- InterfaceAddress{
							Network:   net.IPNet{IP: *device.DHCP.ServerIP, Mask: *device.DHCP.NetworkMask},
							Interface: server.Interface,
							Remove:    true,
						}
					}
				}
			}
		}
	}
}

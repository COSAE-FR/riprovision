package base

import (
	"fmt"
	"github.com/apparentlymart/go-cidr/cidr"
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
	var networks []string
	for _, deviceMAC := range server.cache.Keys() {
		device, found := server.GetDevice(deviceMAC.(string))
		if found && device.DHCP.ServerIP != nil {
			deviceNetwork := &net.IPNet{
				IP:   device.DHCP.ServerIP.Mask(*device.DHCP.NetworkMask),
				Mask: *device.DHCP.NetworkMask,
			}
			networks = append(networks, deviceNetwork.String())
		}
	}
	for available, err := network.GetFreeNetwork(server.DHCP.baseNetwork, server.DHCP.NetworkPrefix); err != nil; {
		if stringInSlice(available.String(), networks) {
			continue
		}

	}
	for {
		available, err := network.GetFreeNetwork(server.DHCP.baseNetwork, server.DHCP.NetworkPrefix)
		if err != nil {
			return nil, err
		}
		if stringInSlice(available.String(), networks) {
			continue
		}
		return available, nil
	}
}

func (server *Server) LocalAddressManager(add chan net.IPNet, remove chan net.IPNet, exit chan int) {
	for {
		select {
		case <-exit:
			return
		case ipNetwork := <-add:
			serverIP, err := cidr.Host(&ipNetwork, 1)
			if err != nil {
				log.Printf("Cannot get server IP: %v", err)
				continue
			}
			err = AddInterfaceIP(serverIP, ipNetwork.Mask, server.Interface)
			if err != nil {
				log.Printf("Cannot add server IP: %v", err)
				continue
			}
			continue
		case ipNetwork := <-remove:
			serverIP, err := cidr.Host(&ipNetwork, 1)
			if err != nil {
				log.Printf("Cannot get server IP: %v", err)
				continue
			}
			err = RemoveInterfaceIP(serverIP, ipNetwork.Mask, server.Interface)
			if err != nil {
				log.Printf("Cannot remove server IP: %v", err)
				continue
			}
			continue
		}
	}
}

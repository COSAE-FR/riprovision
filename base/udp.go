package base

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/krolaw/dhcp4"
	"log"
	"net"
)

type DHCPPacket struct {
	Packet gopacket.Packet
	Ethernet *layers.Ethernet
	IP     *layers.IPv4
	UDP    *layers.UDP
}

func preparePacket(packet gopacket.Packet) (*DHCPPacket, error) {
	pckt := &DHCPPacket{Packet: packet}
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return pckt, errors.New("not an Ethernet packet")
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return pckt, errors.New("not an IP packet")
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return pckt, errors.New("not a UDP packet")
	}
	pckt.Ethernet = ethLayer.(*layers.Ethernet)
	pckt.IP = ipLayer.(*layers.IPv4)
	pckt.UDP = udpLayer.(*layers.UDP)
	return pckt, nil
}

func Serve(in chan gopacket.Packet, out chan []byte, handler dhcp4.Handler) error {
	packetOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for {
		packet := <-in
		dhcpPacket, err := preparePacket(packet)
		if err != nil {
			continue
		}
		n := dhcpPacket.UDP.Length
		if n < 240 { // Packet too small to be DHCP
			continue
		}
		req := dhcp4.Packet(dhcpPacket.UDP.Payload)
		if req.HLen() > 16 { // Invalid size
			continue
		}
		options := req.ParseOptions()
		var reqType dhcp4.MessageType
		if t := options[dhcp4.OptionDHCPMessageType]; len(t) != 1 {
			continue
		} else {
			reqType = dhcp4.MessageType(t[0])
			if reqType < dhcp4.Discover || reqType > dhcp4.Inform {
				continue
			}
		}
		if res := handler.ServeDHCP(req, reqType, options); res != nil {
			// If IP not available, broadcast
			/*ipStr, portStr, err := net.SplitHostPort(addr.String())
			if err != nil {
				return err
			}

			if net.ParseIP(ipStr).Equal(net.IPv4zero) || req.Broadcast() {
				//port, _ := strconv.Atoi(portStr)
				//addr = &net.UDPAddr{IP: net.IPv4bcast, Port: port}
			}
			if _, e := conn.WriteTo(res, addr); e != nil {
				return e
			} */
			conf := *handler.(*Server)
			device, found := conf.GetDevice(dhcpPacket.Ethernet.SrcMAC.String())
			if !found {
				continue
			}
			var ip *layers.IPv4
			if dhcpPacket.IP.SrcIP.Equal(net.IPv4zero) || dhcpPacket.IP.DstIP.Equal(net.IPv4bcast) {
				ip = &layers.IPv4{
					SrcIP:    *device.DHCP.ServerIP,
					DstIP:    net.IPv4bcast,
					Protocol: layers.IPProtocolUDP,
				}
			} else {
				ip = &layers.IPv4{
					SrcIP:    *device.DHCP.ServerIP,
					DstIP:   *device.DHCP.ClientIP,
					Protocol: layers.IPProtocolUDP,
					Version: 4,
					TTL: 64,
				}
			}
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(67),
				DstPort: layers.UDPPort(68),
			}
			udp.Payload = res
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				log.Printf("Cannot set network layer: %v", err)
				continue
			}
			eth := &layers.Ethernet{
				SrcMAC:       conf.Iface.HardwareAddr,
				DstMAC:       dhcpPacket.Ethernet.SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, packetOptions, eth, ip, udp); err != nil {
				log.Printf("Cannot serialize response: %v", err)
				continue
			}
			out <- buffer.Bytes()
		}
	}
}

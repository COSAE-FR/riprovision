package base

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/krolaw/dhcp4"
	log "github.com/sirupsen/logrus"
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

func Serve(in chan gopacket.Packet, out chan OutPacket, handler dhcp4.Handler) error {
	packetOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for {
		select {
		case packet := <-in:
			log.Printf("DHCP: Received a DHCP packet")
			dhcpPacket, err := preparePacket(packet)
			if err != nil {
				log.Printf("DHCP: Cannot prepare packet: %v", err)
				continue
			}
			n := dhcpPacket.UDP.Length
			if n < 240 { // Packet too small to be DHCP
				log.Printf("DHCP: Packet too small: %d", n)
				continue
			}
			req := dhcp4.Packet(dhcpPacket.UDP.Payload)
			if req.HLen() > 16 { // Invalid size
				log.Printf("DHCP: Payload too small: %d", req.HLen())
				continue
			}
			options := req.ParseOptions()
			var reqType dhcp4.MessageType
			if t := options[dhcp4.OptionDHCPMessageType]; len(t) != 1 {
				log.Printf("DHCP: No or too much DHCP message types %d", len(t))
				continue
			} else {
				reqType = dhcp4.MessageType(t[0])
				if reqType < dhcp4.Discover || reqType > dhcp4.Inform {
					log.Printf("DHCP: Wrong message type: %+v", reqType)
					continue
				}
			}
			log.Print("DHCP: Sending packet to DHCP handler")
			if res := handler.ServeDHCP(req, reqType, options); res != nil {
				conf := *handler.(*Server)
				device, found := conf.GetDevice(dhcpPacket.Ethernet.SrcMAC.String())
				if !found {
					log.Printf("Destination device not found: %s", dhcpPacket.Ethernet.SrcMAC.String())
					continue
				}
				var ip *layers.IPv4
				if dhcpPacket.IP.SrcIP.Equal(net.IPv4zero) || dhcpPacket.IP.DstIP.Equal(net.IPv4bcast) {
					ip = &layers.IPv4{
						Version:    4,                    //uint8
						IHL:        5,                    //uint8
						TOS:        0,                    //uint8
						Id:         0,                    //uint16
						Flags:      0,                    //IPv4Flag
						FragOffset: 0,                    //uint16
						TTL:        255,                  //uint8
						Protocol:   layers.IPProtocolUDP, //IPProtocol UDP(17)
						SrcIP:      *device.DHCP.ServerIP,
						DstIP:      net.IPv4bcast,
					}
				} else {
					ip = &layers.IPv4{
						Version:    4,                    //uint8
						IHL:        5,                    //uint8
						TOS:        0,                    //uint8
						Id:         0,                    //uint16
						Flags:      0,                    //IPv4Flag
						FragOffset: 0,                    //uint16
						TTL:        255,                  //uint8
						Protocol:   layers.IPProtocolUDP, //IPProtocol UDP(17)
						SrcIP:      *device.DHCP.ServerIP,
						DstIP:      *device.DHCP.ClientIP,
					}
				}
				udp := &layers.UDP{
					SrcPort: layers.UDPPort(67),
					DstPort: layers.UDPPort(68),
				}
				//udp.Payload = res
				if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
					log.Printf("Cannot set network layer: %v", err)
					continue
				}
				eth := &layers.Ethernet{
					SrcMAC:       conf.Iface.HardwareAddr,
					DstMAC:       dhcpPacket.Ethernet.SrcMAC,
					EthernetType: layers.EthernetTypeIPv4,

				}
				dhcp := gopacket.NewPacket(
					res,
					layers.LayerTypeDHCPv4,
					gopacket.Default,
					)
				var dhcpFound bool
				buffer := gopacket.NewSerializeBuffer()
				if dhcp != nil {
					dhcpLayer := dhcp.Layer(layers.LayerTypeDHCPv4)
					if dhcpLayer != nil {
							if err := gopacket.SerializeLayers(buffer, packetOptions, eth, ip, udp, dhcpLayer.(*layers.DHCPv4)); err != nil { //
								log.Printf("Cannot serialize response: %v", err)
								continue
							}
						dhcpFound = true
					}
				}
				if !dhcpFound {
					if err := gopacket.SerializeLayers(buffer, packetOptions, eth, ip, udp, gopacket.Payload(res)); err != nil { //
						log.Printf("Cannot serialize response: %v", err)
						continue
					}
				}

				log.Printf("Sending DHCP response %+v", eth)
				log.Printf("Sending DHCP response %+v", ip)
				log.Printf("Sending DHCP response %+v", udp)
				log.Printf("Packet layers: %+v", buffer.Layers())
				content := buffer.Bytes()
				pk := gopacket.NewPacket(
					content,
					layers.LayerTypeEthernet,
					gopacket.Default,
				)
				log.Printf("Packet %+v", pk.LinkLayer())
				log.Printf("Packet Net %+v", pk.NetworkLayer())
				log.Printf("Packet Transport %+v", pk.TransportLayer())
				log.Printf("Packet Application %+v", pk.ApplicationLayer())
				dh := pk.Layer(layers.LayerTypeDHCPv4)
				if dh == nil {
					log.Printf("Cannot decode DHCPv4 layer")
				} else {
					dhcp := dh.(*layers.DHCPv4)
					log.Printf("Packet Application %+v", dhcp)
					if err := gopacket.SerializeLayers(buffer, packetOptions, eth, ip, udp, dhcp); err == nil { //
						log.Printf("Serialized in 2nd round")
						out <- NewOutPacket(buffer.Bytes())
						continue
					}
				}
				out <- NewOutPacket(content)
			} else {
				log.Printf("DHCP response is empty or nil")
			}
		}
	}
}

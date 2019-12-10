package base

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/krolaw/dhcp4"
)

type DHCPPacket struct {
	Packet gopacket.Packet
	IP     *layers.IPv4
	UDP    *layers.UDP
}

func preparePacket(packet gopacket.Packet) (*DHCPPacket, error) {
	pckt := &DHCPPacket{Packet: packet}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return pckt, errors.New("not an IP packet")
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return pckt, errors.New("not a UDP packet")
	}
	pckt.IP = ipLayer.(*layers.IPv4)
	pckt.UDP = udpLayer.(*layers.UDP)
	return pckt, nil
}

func Serve(in chan gopacket.Packet, out chan gopacket.Packet, handler dhcp4.Handler) error {

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
		}
	}
}

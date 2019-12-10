package base

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"net"
)

const (
	DHCPPort   = 67
	InformPort = 10001
)

// ARP requests only : (arp[6:2] = 1)
// Our requests "((arp[6:2] = 1) or udp dst port 67 or udp dst port 10001) and not vlan"
type PacketHandler struct {
	handle *pcap.Handle
	iface  *net.Interface
	ARP    chan gopacket.Packet
	Inform chan gopacket.Packet
	DHCP   chan gopacket.Packet
}

func New(iface *net.Interface) (*PacketHandler, error) {
	handler := &PacketHandler{iface: iface}
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Unable to open packet capture on interface %s", iface.Name)
		return handler, err
	}
	handler.handle = handle
	handler.ARP = make(chan gopacket.Packet, 100)
	handler.Inform = make(chan gopacket.Packet, 100)
	handler.DHCP = make(chan gopacket.Packet, 100)

	return handler, nil
}

func (handler *PacketHandler) SetFilter(filter string) error {
	return handler.handle.SetBPFFilter(filter)
}

func (handler *PacketHandler) Close() {
	handler.handle.Close()
}

func (handler *PacketHandler) Listen(stop chan int) {
	log.Printf("Listening on interface %s", handler.iface.Name)
	src := gopacket.NewPacketSource(handler.handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Print("Received a listener kill switch")
			return
		case packet = <-in:
			log.Print("Received a new packet")
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				log.Print("New packet is ARP")
				arp := arpLayer.(*layers.ARP)
				if !bytes.Equal([]byte(handler.iface.HardwareAddr), arp.SourceHwAddress) {
					handler.ARP <- packet
				}
				continue
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				log.Print("New packet is UDP")

				udp := udpLayer.(*layers.UDP)
				if udp.DstPort == InformPort {
					log.Print("New packet is Inform")
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer != nil {
						if bytes.Equal(ipLayer.(*layers.IPv4).DstIP, net.IPv4bcast) {
							handler.Inform <- packet
						}
					}
				} else if udp.DstPort == DHCPPort {
					log.Print("New packet is DHCP")
					handler.DHCP <- packet
				}
			}
		}
	}
}

func (handler *PacketHandler) Write(packet []byte) error {
	return handler.handle.WritePacketData(packet)
}

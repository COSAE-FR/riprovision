package base

import (
	"encoding/binary"
	"errors"
	"github.com/COSAE-FR/riprovision/address"
	"github.com/COSAE-FR/riprovision/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

type DHCPPacket struct {
	Packet   gopacket.Packet
	Ethernet *layers.Ethernet
	IP       *layers.IPv4
	UDP      *layers.UDP
	DHCP     *layers.DHCPv4
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
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return pckt, errors.New("not a DHCP packet")
	}
	pckt.Ethernet = ethLayer.(*layers.Ethernet)
	pckt.IP = ipLayer.(*layers.IPv4)
	pckt.UDP = udpLayer.(*layers.UDP)
	pckt.DHCP = dhcpLayer.(*layers.DHCPv4)
	return pckt, nil
}

func (h *Server) DHCPServer() {
	logger := h.Log.WithFields(log.Fields{
		"component": "DHCP",
	})
	packetOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for {
		select {
		case packet := <-h.Handler.DHCP:
			dhcpPacket, err := preparePacket(packet)
			if err != nil {
				logger.Errorf("Cannot prepare packet: %v", err)
				continue
			}
			n := dhcpPacket.UDP.Length
			if n < 240 { // Packet too small to be DHCP
				log.Errorf("Incoming packet too small: %d", n)
				continue
			}
			if dhcpPacket.DHCP.HardwareLen > 16 {
				logger.Errorf("Incoming packet is malformed: hardware length: %d", dhcpPacket.DHCP.HardwareLen)
				continue
			}
			mac := dhcpPacket.Ethernet.SrcMAC.String()
			logger = logger.WithField("device", mac)
			if dhcpPacket.DHCP.ClientHWAddr.String() != mac {
				logger.Errorf("MAC address mismatch between Ethernet and DHCP packets")
				continue
			}
			if !h.ValidMAC(mac) {
				logger.Error("Unauthorized client")
				continue
			}
			msgType := getDHCPMsgType(dhcpPacket.DHCP)
			logger = logger.WithField("dhcp_msg", msgType.String())
			if msgType == layers.DHCPMsgTypeUnspecified {
				logger.Error("Incoming packet is malformed: Unknown or missing message type")
				continue
			}

			device, found := h.GetDevice(mac)
			reply := layers.DHCPMsgTypeUnspecified
			switch msgType {
			case layers.DHCPMsgTypeDiscover:
				if !found || device == nil {
					deviceLogger := log.WithField("device", mac)
					device = &Device{
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
						logger.Error("No free network")
						continue
					}
					logger.Debugf("DHCP handler: asking for address creation: %s", freeNetwork.String())

					h.ManageNet <- address.InterfaceAddress{
						Network:   *freeNetwork,
						Interface: h.Interface,
					}
					_, targetNetwork, err := net.ParseCIDR(freeNetwork.String())
					if err != nil {
						logger.Errorf("Cannot compute server IP: %v", err)
						continue
					}
					serverIP := network.NextIP(targetNetwork.IP, 1)
					clientIP := network.NextIP(targetNetwork.IP, 2)
					device.DHCP = &DHCPDevice{
						ServerIP:    &serverIP,
						NetworkMask: &freeNetwork.Mask,
						ClientIP:    &clientIP,
						Expiry:      time.Now().Add(h.DHCP.LeaseDuration),
					}
				}
				reply = layers.DHCPMsgTypeOffer
				break
			case layers.DHCPMsgTypeRequest:
				if !found || device == nil {
					logger.Error("DHCP Request message from unknown device")
					continue
				}
				if device.DHCP == nil || device.DHCP.ClientIP == nil {
					logger.Error("DHCP Request message from unprepared device")
					continue
				}
				reqIPOpt, err := getDHCPOption(dhcpPacket.DHCP.Options, layers.DHCPOptRequestIP)
				var reqIP net.IP
				if err != nil {
					logger.Warn("Client hasn't requested an IP")
					reqIP = dhcpPacket.DHCP.ClientIP
				} else {
					reqIP = net.IP(reqIPOpt.Data)
				}
				if len(reqIP) != 4 && reqIP.Equal(net.IPv4zero) {
					logger.Errorf("Invalid requested IP: %s", reqIP.String())
					continue
				}
				if !reqIP.Equal(*device.DHCP.ClientIP) {
					logger.Errorf("Unknown requested IP: %s", reqIP.String())
					continue
				}
				reply = layers.DHCPMsgTypeAck
				break
			case layers.DHCPMsgTypeDecline, layers.DHCPMsgTypeRelease:
				logger.Warn("Client requested its deletion")
				continue
			default:
				continue
			}
			if reply != layers.DHCPMsgTypeUnspecified {
				dhcpReply := createDHCPReply(dhcpPacket.DHCP, reply, device, h.DHCP.LeaseDuration)
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
				if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
					logger.Errorf("Cannot set network layer: %v", err)
					continue
				}
				eth := &layers.Ethernet{
					SrcMAC:       h.Iface.HardwareAddr,
					DstMAC:       dhcpPacket.Ethernet.SrcMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, packetOptions, eth, ip, udp, dhcpReply); err != nil { //
					logger.Errorf("Cannot serialize response: %v", err)
					continue
				}
				h.WriteNet <- NewOutPacket(buffer.Bytes())
				h.AddDevice(device)
			}
		}
	}
}

func createDHCPOptions(msgType layers.DHCPMsgType, device *Device, duration time.Duration) layers.DHCPOptions {
	options := layers.DHCPOptions{}
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptServerID, device.DHCP.ServerIP.To4()))
	if duration > 0 {
		leaseBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(leaseBytes, uint32(duration/time.Second))
		options = append(options, layers.NewDHCPOption(layers.DHCPOptLeaseTime, leaseBytes))
	}
	options = append(options, layers.NewDHCPOption(layers.DHCPOptSubnetMask, *device.DHCP.NetworkMask))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptRouter, device.DHCP.ServerIP.To4()))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptDNS, device.DHCP.ServerIP.To4()))
	return options
}

func getDHCPMsgType(dhcp *layers.DHCPv4) layers.DHCPMsgType {
	option, err := getDHCPOption(dhcp.Options, layers.DHCPOptMessageType)
	if err != nil {
		return layers.DHCPMsgTypeUnspecified
	}
	if len(option.Data) != 1 {
		return layers.DHCPMsgTypeUnspecified
	}
	msgType := layers.DHCPMsgType(option.Data[0])
	if msgType < layers.DHCPMsgTypeDiscover || msgType > layers.DHCPMsgTypeInform {
		return layers.DHCPMsgTypeUnspecified
	}
	return msgType
}

func getDHCPOption(options layers.DHCPOptions, optionType layers.DHCPOpt) (layers.DHCPOption, error) {
	for _, option := range options {
		if option.Type == optionType {
			return option, nil
		}
	}
	return layers.DHCPOption{}, nil
}

func createDHCPReply(request *layers.DHCPv4, msgType layers.DHCPMsgType, device *Device, duration time.Duration) *layers.DHCPv4 {
	options := createDHCPOptions(msgType, device, duration)
	return &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: request.HardwareType,
		HardwareLen:  request.HardwareLen,
		HardwareOpts: request.HardwareOpts,
		Xid:          request.Xid,
		Secs:         request.Secs,
		Flags:        request.Flags,
		ClientIP:     request.ClientIP,
		YourClientIP: device.DHCP.ClientIP.To4(),
		NextServerIP: nil,
		RelayAgentIP: nil,
		ClientHWAddr: request.ClientHWAddr,
		ServerName:   nil,
		File:         nil,
		Options:      options,
	}
}

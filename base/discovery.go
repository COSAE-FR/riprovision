package base

import (
	"encoding/binary"
	"fmt"
	"github.com/gcrahay/riprovision/arp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
	"time"
)

// TagID identifies tags
type TagID uint8

const (
	// common tags
	tagMacAddress = 0x01 // mac addr
	tagIPInfo     = 0x02 // mac addr + ipv4 addr
	tagFirmware   = 0x03 // string
	tagUptime     = 0x0A // uint32
	tagHostname   = 0x0B // string
	tagPlatform   = 0x0C // string
	tagEssid      = 0x0D // string
	tagWmode      = 0x0E // uint8

	// v1 tags
	tagUsername     = 0x06 // string
	tagSalt         = 0x07 // ?
	tagRndChallenge = 0x08 // ?
	tagChallenge    = 0x09 // ?
	tagWebui        = 0x0F // string?
	tagModelV1      = 0x14 // string

	// v2 tags
	tagSequence     = 0x12 // uint?
	tagSourceMac    = 0x13 // string
	tagShortVersion = 0x16 // string
	tagDefault      = 0x17 // uint8 (bool)
	tagLocating     = 0x18 // uint8 (bool)
	tagDhcpc        = 0x19 // uint8 (bool)
	tagDhcpcBound   = 0x1A // uint8 (bool)
	tagReqFirmware  = 0x1B // string
	tagSshdPort     = 0x1C // uint32?
	tagModelV2      = 0x15 // string
)

type tagParser func([]byte) (interface{}, error)

// TagDescription annotates some meta information to a TagID
type TagDescription struct {
	shortName string
	longName  string
	byteLen   int // 0 <= unspec, 0 < length < 2**16, 2**16 >= error
	converter tagParser
}

var (
	tagDescriptions = map[TagID]TagDescription{
		tagEssid:        {"essid", "Wireless ESSID", -1, parseString},
		tagFirmware:     {"firmware", "Firmware", -1, parseString},
		tagHostname:     {"hostname", "Hostname", -1, parseString},
		tagIPInfo:       {"ipinfo", "MAC/IP mapping", 10, parseIPInfo},
		tagMacAddress:   {"hwaddr", "Hardware/MAC address", 6, parseMacAddress},
		tagModelV1:      {"model.v1", "Model name", -1, parseString},
		tagModelV2:      {"model.v2", "Model name", -1, parseString},
		tagPlatform:     {"platform", "Platform information", -1, parseString},
		tagShortVersion: {"short-ver", "Short version", -1, parseString},
		tagSshdPort:     {"sshd-port", "SSH port", 2, parseUint16},
		tagUptime:       {"uptime", "Uptime", 4, parseUint32},
		tagUsername:     {"username", "Username", -1, parseString},
		tagWebui:        {"webui", "URL for Web-UI", -1, nil},
		tagWmode:        {"wmode", "Wireless mode", 1, parseUint8},

		// unknown or not yet found in the wild
		tagChallenge:    {"challenge", "(?)", -1, nil},
		tagDefault:      {"default", "(bool)", 1, parseBool},
		tagDhcpc:        {"dhcpc", "(bool)", 1, parseBool},
		tagDhcpcBound:   {"dhcpc-bound", "(bool)", 1, parseBool},
		tagLocating:     {"locating", "(bool)", 1, parseBool},
		tagReqFirmware:  {"req-firmware", "(string)", -1, parseString},
		tagRndChallenge: {"rnd-challenge", "(?)", -1, nil},
		tagSalt:         {"salt", "(?)", -1, nil},
		tagSequence:     {"seq", "(uint?)", -1, nil},
		tagSourceMac:    {"source-mac", "(?)", -1, nil},
	}
)

// Tag describes a key value pair
type Tag struct {
	ID          TagID
	description *TagDescription
	value       interface{}
}

type ipInfo struct {
	MacAddress net.HardwareAddr
	IPAddress  net.IP
}

// ParseTag converts a byte stream (i.e. an UDP packet slice) into a Tag
func ParseTag(id TagID, n uint16, raw []byte) (*Tag, error) {
	t := &Tag{ID: id}

	// check if known, unknown, or not yet seen
	if d, ok := tagDescriptions[t.ID]; ok {
		t.description = &d
	} else {
		t.description = &TagDescription{
			shortName: "unknown",
			longName:  fmt.Sprintf("unknown (%#x)", t.ID),
		}
	}

	if t.description.byteLen > 0 {
		if t.description.byteLen != int(n) {
			return nil, fmt.Errorf(
				"length mismatch for tag %s (expected %d bytes, got %d)",
				t.description.shortName, t.description.byteLen, n,
			)
		}
		if len(raw) < int(n) {
			return nil, fmt.Errorf(
				"not enough data for tag %s (expected %d bytes, got %d)",
				t.description.shortName, n, len(raw),
			)
		}
	}

	if val, err := t.description.convert(raw); err == nil {
		t.value = val
	} else {
		return nil, err
	}

	return t, nil
}

// Name returns the short tag name
func (t *Tag) Name() string {
	return t.description.shortName
}

// Description returns the long tag name
func (t *Tag) Description() string {
	return t.description.longName
}

// StringInto tries to update the given string reference with a type
// asserted value (it doesn't perform an update, if the type assertion
// fails)
func (t *Tag) StringInto(ref *string) {
	if v, ok := t.value.(string); ok {
		*ref = v
	}
}

func (td *TagDescription) convert(data []byte) (interface{}, error) {
	if td.converter == nil {
		return fmt.Sprintf("len:%d<%x>", len(data), data), nil
	}
	return td.converter(data)
}

func parseString(data []byte) (interface{}, error) {
	return string(data), nil
}

func parseBool(data []byte) (interface{}, error) {
	return uint8(data[0]) != 0, nil
}

func parseUint8(data []byte) (interface{}, error) {
	return uint8(data[0]), nil
}

func parseUint16(data []byte) (interface{}, error) {
	return binary.BigEndian.Uint16(data[0:2]), nil
}

func parseUint32(data []byte) (interface{}, error) {
	return binary.BigEndian.Uint32(data[0:4]), nil
}

func parseMacAddress(data []byte) (interface{}, error) {
	return net.HardwareAddr(data[0:6]), nil
}

func parseIPInfo(data []byte) (interface{}, error) {
	return &ipInfo{
		MacAddress: net.HardwareAddr(data[0:6]),
		IPAddress:  net.IP(data[6:10]),
	}, nil
}


type InformPacket struct {
	Version   uint8
	Tags      []*Tag
	timestamp time.Time
}

// ParsePacket tries to parse UPD packet data into a Packet
func ParseInformPacket(raw []byte) (*InformPacket, error) {
	if len(raw) <= 4 {
		return nil, fmt.Errorf("packet data too short (%d bytes)", len(raw))
	}

	ver := uint8(raw[0])
	cmd := uint8(raw[1])
	length := binary.BigEndian.Uint16(raw[2:4])

	if int(length)+4 != len(raw) {
		return nil, fmt.Errorf("packet length mismatch (expected %d bytes, got %d)", length+4, len(raw))
	}

	p := &InformPacket{
		Version:   ver,
		timestamp: time.Now(),
	}
	if err := p.parse(cmd, raw[4:length+4]); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *InformPacket) parse(cmd uint8, data []byte) error {
	if !(p.Version == 1 && cmd == 0) && p.Version != 2 {
		return fmt.Errorf("unsupported packet ver=%d cmd=%d", p.Version, cmd)
	}

	for curr := 0; curr < len(data); {
		id := TagID(data[curr+0])
		n := binary.BigEndian.Uint16(data[curr+1 : curr+3])
		begin, end := curr+3, curr+3+int(n)

		tag, err := ParseTag(id, n, data[begin:end])
		if err != nil {
			log.Print(err)
		} else {
			p.Tags = append(p.Tags, tag)
		}

		curr = end
	}

	return nil
}

func (p *InformPacket) Device() *UnifiDevice {
	dev := &UnifiDevice{
		IPAddresses:    make(map[string][]string),
	}

	for _, t := range p.Tags {
		switch t.ID {
		case tagModelV1, tagModelV2:
			t.StringInto(&dev.Model)
		case tagPlatform:
			t.StringInto(&dev.Platform)
		case tagFirmware:
			t.StringInto(&dev.Firmware)
		case tagEssid:
			t.StringInto(&dev.Essid)
		case tagHostname:
			t.StringInto(&dev.Hostname)

		case tagMacAddress:
			if v, ok := t.value.(net.HardwareAddr); ok {
				dev.DeclaredMacAddress = v.String()
			}
		case tagUptime:
			if v, ok := t.value.(uint32); ok {
				now := time.Now()
				dur := -1 * int(v)
				dev.UpSince = now.Add(time.Duration(dur) * time.Second)
			}
		case tagWmode:
			if v, ok := t.value.(uint8); ok {
				switch v {
				case 2:
					dev.WirelessMode = "Station"
				case 3:
					dev.WirelessMode = "AccessPoint"
				default:
					dev.WirelessMode = fmt.Sprintf("unknown (%#02x)", v)
				}
			}
		case tagIPInfo:
			if v, ok := t.value.(*ipInfo); ok {
				m := v.MacAddress.String()
				dev.IPAddresses[m] = append(dev.IPAddresses[m], v.IPAddress.String())
			}
		}
	}
	return dev
}

func (server *Server) HandleInform(in chan gopacket.Packet) {
	log.Debug("Starting Inform packet handler")
	for {
		select {
		case packet := <- in:
			log.Debugln("Received a new Inform packet")
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				log.Error("Cannot parse Ethernet layer of packet")
				continue
			}
			ethernet := ethLayer.(*layers.Ethernet)
			mac := ethernet.SrcMAC.String()
			logger := log.WithField("device", mac)
			if !server.validMAC(mac) {
				logger.Error("Unauthorized MAC address")
				continue
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				inform, err :=ParseInformPacket(udp.Payload)
				if err != nil {
					logger.Error("Cannot parse packet payload")
					continue
				}
				unifiDevice := inform.Device()
				if unifiDevice.DeclaredMacAddress != mac && false {
					logger.Errorf("Declared MAC differs from source MAC in packet: %s", unifiDevice.DeclaredMacAddress)
					continue
				}
				device, found := server.GetDevice(mac)
				if !found {
					if server.DHCP.Enable {
						logger.Error("Unknown device: cannot accept new devices when DHCP is enabled")
						continue
					}
					device = Device{
						MacAddress: mac,
						Unifi:      unifiDevice,
						DHCP:       nil,
						Log: logger,
					}
				} else {
					device.Unifi = unifiDevice
				}
				provision := server.NewProvisionDevice(&device)
				device.Unifi.Provision = provision
				log.Debugf("Adding Device: \n%s", device.String())
				server.AddDevice(device)
			} else {
				log.Debug("Cannot parse UDP layer of Inform packet")
			}
		}
	}
}

func (server *Server) NewProvisionDevice(dev *Device) *UnifiProvision {
	seen := make(map[string]int) // IP address -> # of devices with this address
	var newDevice *UnifiProvision

	if dev.Unifi != nil && dev.Unifi.Provision != nil {
		newDevice = dev.Unifi.Provision
	} else {
		newDevice = &UnifiProvision{}
	}

	for _, addrs := range dev.Unifi.IPAddresses {
		for _, ip := range addrs {
			seen[ip]++
		}
	}

	macEntries := arp.ReverseSearch(dev.MacAddress)
	for _, macEntry := range macEntries {
		if macEntry.Permanent != true {
			dev.Log.Warnf("Non permanent MAC entry, searching: %+v", macEntry)
			continue
		}
		newDevice.Iface = macEntry.Iface
		if server.validMAC(dev.MacAddress) {
			macIP := net.ParseIP(macEntry.IPAddress)
			if macIP == nil {
				dev.Log.Warnf("Cannot parse MAC address table provided IP: %s", macEntry.IPAddress)
				continue
			}
			newDevice.IP = &macIP
			netInterface, err := net.InterfaceByName(macEntry.Iface)
			if err == nil {
				addresses, err := netInterface.Addrs()
				if err == nil {
					for _, a := range addresses {
						switch v := a.(type) {
						case *net.IPAddr:
							if v.IP.To4() != nil {
								mask := v.IP.DefaultMask()
								newDevice.Mask = &mask
								newDevice.Gateway = v.IP.String()
							}
						case *net.IPNet:
							if v.IP.To4() != nil {
								newDevice.Mask = &v.Mask
								newDevice.Gateway = v.IP.String()
							}
						default:
							continue
						}
					}
				}
			}
		}

		newDevice.VLAN = 1
		parts := strings.Split(newDevice.Iface, ".")
		log.Printf("Device parts len %d", len(parts))
		if len(parts) == 2 {
			vlan, err := strconv.Atoi(parts[1])
			if err == nil {
				newDevice.VLAN = vlan
			} else {
				log.Printf("Cannot convert VLAN to int %s", parts[1])
			}
		}

	}

	return newDevice

}

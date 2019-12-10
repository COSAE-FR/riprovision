package base

import (
	"net"
	"time"
)

type UnifiProvision struct {
	IP      *net.IP
	Mask    *net.IPMask
	VLAN    int
	Gateway string
	Iface   string
}

type UnifiDevice struct {
	Model        string
	Platform     string
	Hostname     string
	Firmware     string
	IPAddresses  map[string][]string
	UpSince      time.Time
	Essid        string
	WirelessMode string
	Provision    *UnifiProvision
}

type DHCPDevice struct {
	ServerIP    *net.IP
	NetworkMask *net.IPMask
	ClientIP    *net.IP
	Expiry      time.Time
}

type Device struct {
	MacAddress string
	Unifi      *UnifiDevice
	DHCP       *DHCPDevice
}

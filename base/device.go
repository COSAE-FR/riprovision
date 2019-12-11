package base

import (
	"github.com/gcrahay/riprovision/network"
	log "github.com/sirupsen/logrus"
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
	DeclaredMacAddress string
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
	Log *log.Entry
}

func (d *Device) String() string {
	now := time.Now()
	buf := "# General details about the device\n"
	buf += "\n  MAC:           " + d.MacAddress
	if d.DHCP != nil {
		buf += "\n\n# DHCP details\n"
		buf += "\nServer:		" + d.DHCP.ServerIP.String()
		buf += "\nClient:		" + d.DHCP.ClientIP.String()
		buf += "\nMask:			" + network.FormatMask(*d.DHCP.NetworkMask)
	}
	if d.Unifi != nil {
		buf += "\n\n# Unifi details\n"
		buf += "\n  Model:         " + d.Unifi.Model
		buf += "\n  Platform:      " + d.Unifi.Platform
		buf += "\n  Firmware:      " + d.Unifi.Firmware
		buf += "\n  Hostname:      " + d.Unifi.Hostname
		if (d.Unifi.UpSince != time.Time{}) {
			buf += "\n  Booted at:     " + d.Unifi.UpSince.Format(time.RFC3339)
			buf += "\n  booted:        " + now.Sub(d.Unifi.UpSince).String() + " ago"
		}
		for mac, ips := range d.Unifi.IPAddresses {
			buf += "\n  IP addresses on interface " + mac + ":"
			for _, ip := range ips {
				buf += "\n    - " + ip
			}
		}

		if d.Unifi.Essid != "" {
			buf += "\n  ESSID:         " + d.Unifi.Essid
		}
		if d.Unifi.WirelessMode != "" {
			buf += "\n  WMode:         " + d.Unifi.WirelessMode
		}

		if d.Unifi.Provision != nil {
			buf += "\n\n# Provisioning details\n"
			buf += "\n  IP:         " + d.Unifi.Provision.IP.String()
			buf += "\n  Mask:       " + network.FormatMask(*d.Unifi.Provision.Mask)
			buf += "\n  Gateway:    " + d.Unifi.Provision.Gateway
			buf += "\n  Interface:  " + d.Unifi.Provision.Iface
		}
	}
	return buf
}
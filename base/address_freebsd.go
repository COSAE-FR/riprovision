// +build freebsd

package base

import (
	log "github.com/sirupsen/logrus"
	"net"
	"os/exec"
)

func AddInterfaceIP(ip net.IP, mask net.IPMask, iface string) error {
	msk := net.IPv4(mask[0], mask[1], mask[2], mask[3]).String()
	log.Printf("Adding interface address: ifconfig %s %s netmask %s alias", iface, ip.String(), msk)
	cmd := exec.Command("ifconfig", iface, ip.String(), "netmask", msk, "alias")
	out, err := cmd.CombinedOutput()
	log.Printf("CMD outputs error: %v", err)
	log.Printf("Out:\n%s", string(out))
	return err
}

func RemoveInterfaceIP(ip net.IP, mask net.IPMask, iface string) error {
	msk := net.IPv4(mask[0], mask[1], mask[2], mask[3]).String()
	log.Printf("Removing interface address: ifconfig %s %s netmask %s delete", iface, ip.String(), msk)
	cmd := exec.Command("ifconfig", iface, ip.String(), "netmask",msk, "delete")
	out, err := cmd.CombinedOutput()
	log.Printf("CMD outputs error: %v", err)
	log.Printf("Out:\n%s", string(out))
	return err
}

// +build linux

package base

import (
	"fmt"
	"net"
	"os/exec"
)

func AddInterfaceIP(ip net.IP, mask net.IPMask, iface string) error {
	bits, _ := mask.Size()
	address := fmt.Sprintf("%s/%d", ip.String(), bits)
	cmd := exec.Command("ifconfig", "add", address, "dev", iface)
	return cmd.Run()
}

func RemoveInterfaceIP(ip net.IP, mask net.IPMask, iface string) error {
	bits, _ := mask.Size()
	address := fmt.Sprintf("%s/%d", ip.String(), bits)
	cmd := exec.Command("ifconfig", "del", address, "dev", iface)
	return cmd.Run()
}

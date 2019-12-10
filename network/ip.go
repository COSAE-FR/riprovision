package network

import (
	"errors"
	"github.com/apparentlymart/go-cidr/cidr"
	"log"
	"net"
)

func GetLocalIPs() (ips []string) {
	foo, err := net.InterfaceAddrs()

	if err == nil {
		for _, v := range foo {
			ips = append(ips, v.String())
		}
	}
	return
}

func GetLocalNetworks() (nets []net.IPNet) {
	for _, ip := range GetLocalIPs() {
		_, network, err := net.ParseCIDR(ip)
		if err == nil {
			nets = append(nets, *network)
		}
	}
	return
}

func NetworkOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}

func NetworkOverlapsLocalNetwork(n *net.IPNet) bool {
	for _, localNet := range GetLocalNetworks() {
		if NetworkOverlap(&localNet, n) {
			return true
		}
	}
	return false
}

func NetworkOverlapsBlacklist(n *net.IPNet, bl[]net.IPNet) bool {
	for _, blNet := range bl {
		if NetworkOverlap(&blNet, n) {
			return true
		}
	}
	return false
}

func GetFreeNetwork(base *net.IPNet, prefixLen int) (*net.IPNet, error) {
	for candidate, end := cidr.NextSubnet(base, prefixLen); end != true; {
		if !NetworkOverlapsLocalNetwork(candidate) {
			return candidate, nil
		}
	}
	return &net.IPNet{}, errors.New("no available network")
}

func GetFreeNetworkBlacklist(base *net.IPNet, prefixLen int, bl []net.IPNet) (*net.IPNet, error) {
	candidate := &net.IPNet{IP:base.IP, Mask: net.CIDRMask(prefixLen, 32)}
	for  {
		candidate, end := cidr.NextSubnet(candidate, prefixLen)
		if end {
			log.Printf("No network available")
			break
		}
		log.Printf("Testing network %s", candidate.String())
		if !NetworkOverlapsLocalNetwork(candidate) && !NetworkOverlapsBlacklist(candidate, bl) {
			log.Printf("Candidate %s found!", candidate.String())
			return candidate, nil
		}
		log.Printf("Network %s is in use", candidate.String())
	}
	log.Printf("No network available, finally")
	return &net.IPNet{}, errors.New("no available network")
}

func GetIPForInterface(interfaceName string) (ipAddress *net.IPNet, err error) {
	interfaces, _ := net.Interfaces()
	for _, inter := range interfaces {
		if inter.Name == interfaceName {
			if addrs, err := inter.Addrs(); err == nil {
				for _, addr := range addrs {
					switch ip := addr.(type) {
					case *net.IPNet:
						if ip.IP.To4() != nil {
							return ip, nil
						}
					}
				}
			}
		}
	}
	return ipAddress, errors.New("no IP found")
}

func NextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

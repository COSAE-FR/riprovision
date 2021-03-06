package address

import (
	"github.com/COSAE-FR/riprovision/network"
	log "github.com/sirupsen/logrus"
	"net"
)

type InterfaceAddress struct {
	Network net.IPNet
	Interface string
	Remove bool
}

func ManageAddress(ipNetwork InterfaceAddress) error {
	action := "add"
	if ipNetwork.Remove {
		action = "remove"
	}
	logger := log.WithFields(log.Fields{
		"app": "riprovision",
		"process": "address",
		"network": ipNetwork.Network.String(),
		"action": action,
	})
	logger.Debug("Address manager called")
	_, targetNetwork, err := net.ParseCIDR(ipNetwork.Network.String())
	if err != nil {
		logger.Errorf("Cannot get server IP: %+v", err)
		return err
	}
	if targetNetwork.IP.To4() == nil {
		logger.Errorf("Not an IPv4: %s", targetNetwork.IP.String())
		return err
	}
	if targetNetwork.IP.Equal(net.IPv4zero) || targetNetwork.IP.Equal(net.IPv4bcast) {
		logger.Errorf("Forbidden IP: %s", targetNetwork.IP.String())
		return err
	}
	prefixSize, maskSize := targetNetwork.Mask.Size()
	if maskSize != 32 || prefixSize < 8 || prefixSize > 30 {
		logger.Errorf("Invalid mask: %s", targetNetwork.Mask.String())
		return err
	}
	_ , err = net.InterfaceByName(ipNetwork.Interface)
	if err != nil {
		logger.Errorf("Unknown interface %s: %+v", ipNetwork.Interface, err)
		return err
	}
	serverIP := network.NextIP(targetNetwork.IP, 1)
	if ipNetwork.Remove {
		err = RemoveInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
		if err != nil {
			logger.Errorf("Cannot remove server IP: %v", err)
			return err
		}
	} else {
		err = AddInterfaceIP(serverIP, ipNetwork.Network.Mask, ipNetwork.Interface)
		if err != nil {
			logger.Errorf("Cannot add server IP: %v", err)
			return err
		}
		return nil
	}
	return nil
}


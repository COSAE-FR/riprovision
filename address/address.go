package address

import (
	"github.com/gcrahay/riprovision/network"
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
		"app": "riproision",
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


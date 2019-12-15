package address

import (
	"github.com/natefinch/pie"
	log "github.com/sirupsen/logrus"
	"net/rpc/jsonrpc"
	"os"
)

type manager struct {
	log *log.Entry
}

func Setup() {
	log.SetOutput(os.Stderr)
	logger := log.WithFields(log.Fields{
		"app": "riproision",
		"process": "address",
		"action": "setup",
	})
	logger.Debug("Starting Address Manager")
	p := pie.NewProvider()
	if err := p.RegisterName("AddressManager", manager{log: logger}); err != nil {
		logger.Fatalf("failed to register Manager: %s", err)
	}
	p.ServeCodec(jsonrpc.NewServerCodec)
}

func (m manager) Manage(ipNetwork *InterfaceAddress, response *string) error {
	logger := m.log.WithFields(log.Fields{
		"action": "manager",
		"network": ipNetwork.Network.String(),
	})
	logger.Debug("New request")
	err := ManageAddress(*ipNetwork)
	if err == nil {
		logger.Debug("Succeeded")
		*response = "OK "+ipNetwork.Network.String()
	} else {
		logger.Errorf("Failed: %v", err)
		*response = "NOK "+ipNetwork.Network.String()
	}
	return err
}


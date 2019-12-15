package address

import (
	"github.com/natefinch/pie"
	log "github.com/sirupsen/logrus"
	"gopkg.in/hlandau/svcutils.v1/exepath"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
)

type Manager struct {
	client *rpc.Client
}

func (m *Manager) Manage(ipNetwork *InterfaceAddress) (result string, err error) {
	err = m.client.Call("AddressManager.manager", ipNetwork, &result)
	return result, err
}

func SetupAddressClient() (Manager, error) {
	client, err := pie.StartProviderCodec(jsonrpc.NewClientCodec, os.Stderr, exepath.Abs, "__ADDRESS_MGR__")
	if err != nil {
		log.Fatalf("Error running address manager: %s", err)
		return Manager{},  err
	}
	p := Manager{client}
	return p, nil
}




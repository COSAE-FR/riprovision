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
	err = m.client.Call("AddressManager.Manage", ipNetwork, &result)
	return result, err
}

func (m *Manager) Configure(settings *ManagerSettings) (result string, err error) {
	err = m.client.Call("AddressManager.Configure", settings, &result)
	return result, err
}

func SetupAddressClient(out *os.File) (Manager, error) {
	client, err := pie.StartProviderCodec(jsonrpc.NewClientCodec, out, exepath.Abs, "__ADDRESS_MGR__")
	if err != nil {
		log.Fatalf("Error running address manager: %s", err)
		return Manager{},  err
	}
	p := Manager{client}
	return p, nil
}




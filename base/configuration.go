package base

import (
	"fmt"
	pssh "github.com/gcrahay/riprovision/ssh"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
)

type dhcpConfiguration struct {
	Enable        bool   `yaml:"enable"`
	BaseNetwork   string `yaml:"base_network"`
	baseNetwork   *net.IPNet
	NetworkPrefix int `yaml:"network_prefix"`
}

type sshAuthMethod struct {
	Type     string `yaml:"type"`
	Password string `yaml:"password"`
	Path     string `yaml:"path"`
}

type SSHConfiguration struct {
	Usernames      []string
	SSHAuthMethods []sshAuthMethod `yaml:"methods"`
	sshAuthMethods []ssh.AuthMethod
}

type configurationTemplates map[string]string

type provisionConfiguration struct {
	InterfaceNames []string               `yaml:"provision_interfaces"`
	SyslogPort     int                    `yaml:"syslog_port"`
	SSH            SSHConfiguration       `yaml:"ssh"`
	Templates      configurationTemplates `yaml:"config_templates"`
}

type Server struct {
	Interface string `yaml:"interface"`
	Iface     *net.Interface

	MaxDevices int `yaml:"max_devices"`
	MACPrefix  []string

	Provision provisionConfiguration `yaml:"provision"`
	DHCP      dhcpConfiguration      `yaml:"dhcp"`

	Handler *PacketHandler

	AddNet    chan net.IPNet
	RemoveNet chan net.IPNet
	StopNet   chan int

	WriteNet  chan []byte
	StopWrite chan int

	cache *lru.Cache
}

func WritePacket(out chan []byte, exit chan int, handler *PacketHandler) {
	for {
		select {
		case <-exit:
			return
		case pckt := <-out:
			handler.Write(pckt)
			continue

		}
	}

}

func (server *Server) Start() error {
	server.StopWrite = make(chan int)
	server.WriteNet = make(chan []byte, 100)
	go WritePacket(server.WriteNet, server.StopWrite, server.Handler)
	return nil
}

func (server *Server) Stop() error {
	// Stop the service here
	if server.DHCP.Enable {
		server.StopNet <- 1
	}
	server.StopWrite <- 1
	return nil
}

func (server *Server) AddDevice(device Device) bool {
	return server.cache.Add(device.MacAddress, device)

}

func (server *Server) GetDevice(mac string) (Device, bool) {
	device, ok := server.cache.Get(mac)
	return device.(Device), ok
}

func (server *Server) HasDevice(mac string) bool {
	return server.cache.Contains(mac)
}

// LoadConfig reads a YAML file and converts it to a Server object
func LoadConfig(fileName string) (c *Server, errs []error) {
	c = &Server{}

	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		errs = append(errs, err)
		return
	}
	if err := yaml.Unmarshal(file, &c); err != nil {
		errs = append(errs, err)
		return
	}

	// the following errors are recoverable

	if len(c.Interface) == 0 {
		errs = append(errs, fmt.Errorf("missing option interfaces, at least one name (or '*') must be given"))
	}

	c.Iface, err = net.InterfaceByName(c.Interface)
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot find listening interface"))
	}

	if len(c.Provision.InterfaceNames) == 0 {
		errs = append(errs, fmt.Errorf("missing option provision_interfaces, at least one name must be given"))
	}

	if len(c.Provision.SSH.Usernames) == 0 {
		c.Provision.SSH.Usernames = append(c.Provision.SSH.Usernames, "ubnt")
	}

	if c.Provision.SyslogPort == 0 {
		c.Provision.SyslogPort = 514
	}

	c.Provision.SSH.sshAuthMethods = make([]ssh.AuthMethod, 0, len(c.Provision.SSH.SSHAuthMethods))
	for _, m := range c.Provision.SSH.SSHAuthMethods {
		switch m.Type {
		case "", "password": // Type=="" is an alias for password
			if m.Password != "" {
				c.Provision.SSH.sshAuthMethods = append(c.Provision.SSH.sshAuthMethods, ssh.Password(m.Password))
			}
		case "ssh-agent":
			if a := pssh.Agent(); a != nil {
				c.Provision.SSH.sshAuthMethods = append(c.Provision.SSH.sshAuthMethods, a)
			}
		case "keyfile":
			if key, ok := pssh.ReadPrivateKey(m.Path, m.Password); ok {
				c.Provision.SSH.sshAuthMethods = append(c.Provision.SSH.sshAuthMethods, key)
			}
		default:
			errs = append(errs, fmt.Errorf("unknown auth method %q", m.Type))
		}
	}

	if c.MaxDevices == 0 {
		c.MaxDevices = 10
	}

	if c.DHCP.Enable {
		if c.DHCP.BaseNetwork == "" {
			c.DHCP.BaseNetwork = "192.168.0.0/16"
		}
		if c.DHCP.NetworkPrefix == 0 {
			c.DHCP.NetworkPrefix = 27
		}

	}
	_, c.DHCP.baseNetwork, err = net.ParseCIDR(c.DHCP.BaseNetwork)
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot parse DHCP base network %s", c.DHCP.BaseNetwork))
	}

	c.cache, err = lru.New(c.MaxDevices)

	if err != nil {
		errs = append(errs, err)
	}

	return
}

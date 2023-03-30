package base

import (
	"fmt"
	"github.com/COSAE-FR/riprovision/address"
	pssh "github.com/COSAE-FR/riprovision/ssh"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"time"
)

type dhcpConfiguration struct {
	Enable        bool   `yaml:"enable"`
	BaseNetwork   string `yaml:"base_network"`
	baseNetwork   *net.IPNet
	NetworkPrefix int `yaml:"network_prefix"`
	LeaseMinutes  int `yaml:"lease_duration"`
	LeaseDuration time.Duration
}

type sshAuthMethod struct {
	Type     string `yaml:"type"`
	Password string `yaml:"password"`
	Path     string `yaml:"path"`
}

type SSHConfiguration struct {
	Usernames      []string        `yaml:"users"`
	SSHAuthMethods []sshAuthMethod `yaml:"methods"`
	sshAuthMethods []ssh.AuthMethod
}

type configurationTemplates map[string]string
type configurationModels map[string]string

type provisionConfiguration struct {
	InterfaceNames []string               `yaml:"provision_interfaces"`
	SyslogPort     int                    `yaml:"syslog_port"`
	SSH            SSHConfiguration       `yaml:"ssh"`
	Models         configurationModels    `yaml:"models"`
	Templates      configurationTemplates `yaml:"templates"`
}

type Server struct {
	Interface string `yaml:"interface"`
	Iface     *net.Interface

	LogLevel      string `yaml:"log_level"`
	LogFile       string `yaml:"log_file"`
	LogFileWriter *os.File
	Log           *log.Entry

	MaxDevices int      `yaml:"max_devices"`
	MACPrefix  []string `yaml:"mac_prefixes"`

	Provision provisionConfiguration `yaml:"provision"`
	DHCP      dhcpConfiguration      `yaml:"dhcp"`

	Handler *PacketHandler

	NetManager address.Manager // RPC client to talk to the interface address manager
	ManageNet  chan address.InterfaceAddress
	StopNet    chan int

	WriteNet  chan OutPacket
	StopWrite chan int

	StopListen chan int

	StopClean   chan int
	CleanTicker *time.Ticker

	Cache *lru.Cache
}

type OutPacket struct {
	data []byte
	len  int
}

func NewOutPacket(data []byte) OutPacket {
	return OutPacket{
		data: data,
		len:  len(data),
	}
}

func WritePacket(out chan OutPacket, exit chan int, handler *PacketHandler) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "packet_writer",
	})
	logger.Debugf("Packet writer started")
	for {
		select {
		case <-exit:
			return
		case pckt := <-out:
			if len(pckt.data) != pckt.len {
				logger.Errorf("Lengths differ: announced %d vs computed %d", pckt.len, len(pckt.data))
				continue
			}
			logger.Debugf("New packet to write: %d", pckt.len)
			err := handler.Write(pckt.data)
			if err != nil {
				logger.Errorf("Write packet: error while writing: %+v", err)
			} else {
				logger.Debugf("Successful write")
			}
			continue

		}
	}

}

func (server *Server) Start() error {
	logger := server.Log.WithFields(log.Fields{
		"component": "start",
	})
	logger.Info("Starting server")
	server.StopListen = make(chan int)
	server.StopWrite = make(chan int)
	server.WriteNet = make(chan OutPacket, 100)
	server.StopClean = make(chan int)
	if server.DHCP.Enable {
		logger.Debug("Starting DHCP components")
		go server.DHCPServer()
		server.CleanTicker = time.NewTicker(server.DHCP.LeaseDuration)
		go server.LocalAddressCLeaner()
	}
	go server.Handler.Listen(server.StopListen)
	go server.HandleInform(server.Handler.Inform)
	go WritePacket(server.WriteNet, server.StopWrite, server.Handler)
	return nil
}

func (server *Server) Stop() error {
	logger := server.Log.WithFields(log.Fields{
		"component": "stop",
	})
	logger.Info("Stopping server")
	server.StopListen <- 1
	server.StopClean <- 1
	if server.DHCP.Enable {
		for _, deviceKeyInt := range server.Cache.Keys() {
			device, found := server.GetDevice(deviceKeyInt.(string))
			if found && device != nil {
				if device.DHCP != nil && device.DHCP.ServerIP != nil {
					server.ManageNet <- address.InterfaceAddress{
						Network: net.IPNet{
							IP:   *device.DHCP.ServerIP,
							Mask: *device.DHCP.NetworkMask,
						},
						Interface: server.Interface,
						Remove:    true,
					}
				}
			}
		}
		server.StopNet <- 1
	}
	server.StopWrite <- 1
	if server.LogFileWriter != nil && server.LogFileWriter.Fd() > 0 {
		_ = server.LogFileWriter.Sync()
		_ = server.LogFileWriter.Close()
	}
	return nil
}

func (server *Server) AddDevice(device *Device) bool {
	if device.Unifi != nil && device.Unifi.Provision != nil {
		device.Unifi.Provision.Configuration = &server.Provision
	}
	return server.Cache.Add(device.MacAddress, device)

}

func (server *Server) GetDevice(mac string) (*Device, bool) {
	device, ok := server.Cache.Get(mac)
	if ok {
		deviceObject, castOk := device.(*Device)
		if castOk && deviceObject != nil {
			if deviceObject.Unifi != nil && deviceObject.Unifi.Provision != nil {
				deviceObject.Unifi.Provision.Configuration = &server.Provision
			}
			return deviceObject, true
		}
	}
	return nil, false
}

func (server *Server) HasDevice(mac string) bool {
	return server.Cache.Contains(mac)
}

// LoadConfig reads a YAML file and converts it to a Server object
func LoadConfig(fileName string) (c *Server, errs []error) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "config_loader",
	})
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

	if len(c.LogLevel) == 0 {
		c.LogLevel = "error"
	}
	logLevel, err := log.ParseLevel(c.LogLevel)
	if err != nil {
		logLevel = log.ErrorLevel
	}
	log.SetLevel(logLevel)

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
			} else {
				logger.Warnf("Cannot add SSH keyfile %s", m.Path)
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
		if c.DHCP.LeaseMinutes == 0 {
			c.DHCP.LeaseMinutes = 10
		}
		c.DHCP.LeaseDuration = time.Duration(c.DHCP.LeaseMinutes) * time.Minute
	}
	_, c.DHCP.baseNetwork, err = net.ParseCIDR(c.DHCP.BaseNetwork)
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot parse DHCP base network %s", c.DHCP.BaseNetwork))
	}

	return
}

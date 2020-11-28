package main

import (
	"errors"
	"fmt"
	"github.com/COSAE-FR/riprovision/address"
	"github.com/COSAE-FR/riprovision/base"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/service.v2"
	"net"
	"os"
)

const (
	NoDHCPFilter = "ip and udp dst port 10001 and not vlan"
	GlobalFilter = "ip and (udp dst port 67 or udp dst port 10001) and not vlan"
)

const Version = "0.10.1"

type Config struct {
	File string `usage:"Provision configuration file" default:"provision.yml"`
}

func New(cfg Config) (*base.Server, error) {
	var err error
	configuration, errs := base.LoadConfig(cfg.File)
	logLevel, err := log.ParseLevel(configuration.LogLevel)
	if err != nil {
		logLevel = log.WarnLevel
	}
	log.SetLevel(logLevel)
	configuration.Log = log.WithFields(log.Fields{
		"app":     "riprovision",
		"version": Version,
	})
	logger := configuration.Log.WithFields(log.Fields{
		"component": "privileged_init",
	})
	if len(configuration.LogFile) > 0 {
		f, err := os.OpenFile(configuration.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err == nil {
			configuration.LogFileWriter = f
			log.SetOutput(f)
		} else {
			logger.Errorf("Cannot open log file %s. Logging to stderr.", configuration.LogFile)
		}

	} else {
		configuration.LogFileWriter = os.Stderr
	}
	if len(errs) > 0 {
		logger.Errorf("Found %d error(s) loading the config file:", len(errs))
		for i, e := range errs {
			logger.Errorf("Error %d: %s", i, e.Error())
		}
		return configuration, errors.New("errors when parsing config file")
	}

	// Create capturing server
	logger.Infof("Starting capturing server on interface %s", configuration.Interface)
	configuration.Handler, err = base.NewHandler(configuration.Iface)
	if err != nil {
		return configuration, fmt.Errorf("cannot bind to interface %s", configuration.Interface)
	}
	logger.Debugf("Capturing server started")
	if configuration.DHCP.Enable {
		logger.Debugf("Setting capturing filter: %s", GlobalFilter)
		err = configuration.Handler.SetFilter(GlobalFilter)
	} else {
		logger.Debugf("Setting capturing filter: %s", NoDHCPFilter)
		err = configuration.Handler.SetFilter(NoDHCPFilter)
	}
	if err != nil {
		logger.Errorf("cannot set capturing server filter: %v", err)
	}

	if configuration.DHCP.Enable {
		logger.Infof("Creating interface IP address handler")
		configuration.ManageNet = make(chan address.InterfaceAddress, 100)
		configuration.StopNet = make(chan int)

		configuration.NetManager, err = address.SetupAddressClient(configuration.LogFileWriter)
		if err != nil {
			logger.Errorf("Cannot setup Address Manager client: %v", err)
			return configuration, err
		}
		_, err = configuration.NetManager.Configure(&address.ManagerSettings{LogLevel: configuration.LogLevel})
		if err != nil {
			logger.Errorf("Cannot configure Address Manager server: %v", err)
		}
		go configuration.RemoteAddressManager(configuration.ManageNet, configuration.StopNet)

		configuration.Cache, err = lru.NewWithEvict(configuration.MaxDevices, func(key interface{}, value interface{}) {
			if value != nil {
				device := value.(base.Device)
				if device.DHCP != nil && device.DHCP.ServerIP != nil {
					configuration.ManageNet <- address.InterfaceAddress{
						Network:   net.IPNet{IP: *device.DHCP.ServerIP, Mask: *device.DHCP.NetworkMask},
						Interface: configuration.Interface,
						Remove:    true,
					}
				}
			}
		})
		if err != nil {
			logger.Errorf("cannot create device cache: %v", err)
			return configuration, errors.New("cannot create device cache")
		}
	} else {
		configuration.Cache, err = lru.New(configuration.MaxDevices)
		if err != nil {
			logger.Debugf("cannot create device cache: %v", err)
			return configuration, errors.New("cannot create device cache")
		}
	}

	return configuration, nil
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		QuoteEmptyFields:       true,
	})
	log.SetOutput(os.Stderr)

	args := os.Args[1:]
	if len(args) == 1 && args[0] == "__ADDRESS_MGR__" {
		address.Setup()
	} else {
		logger := log.WithFields(log.Fields{
			"app":       "riprovision",
			"component": "main",
		})
		cfg := Config{}

		configurator := &easyconfig.Configurator{
			ProgramName: "provision",
		}

		err := easyconfig.Parse(configurator, &cfg)
		if err != nil {
			logger.Fatalf("%v", err)
		}
		logger.Debugf("Started with %#v", cfg)
		service.Main(&service.Info{
			Name:      "riprovision",
			AllowRoot: true,
			NewFunc: func() (service.Runnable, error) {
				return New(cfg)
			},
		})
	}
}

package main

import (
	"errors"
	"fmt"
	"github.com/gcrahay/riprovision/base"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/service.v2"
	"net"
	"os"
)

const (
	NoDHCPFilter = "(udp dst port 10001) and not vlan"
	GlobalFilter = "(udp dst port 67 or udp dst port 10001) and not vlan"
)

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
	if len(errs) > 0 {
		log.Errorf("Found %d error(s) loading the config file:", len(errs))
		for i, e := range errs {
			log.Debugf("Error %d: %s", i, e.Error())
		}
		return configuration, errors.New("errors when parsing config file")
	}

	// Create capturing server
	log.Infof("Starting capturing server on interface %s", configuration.Interface)
	configuration.Handler, err = base.New(configuration.Iface)
	if err != nil {
		return configuration, fmt.Errorf("cannot bind to interface %s", configuration.Interface)
	}
	log.Debugf("Capturing server started")
	if configuration.DHCP.Enable {
		log.Debugf("Setting capturing filter: %s", GlobalFilter)
		err = configuration.Handler.SetFilter(GlobalFilter)
	} else {
		log.Debugf("Setting capturing filter: %s", NoDHCPFilter)
		err = configuration.Handler.SetFilter(NoDHCPFilter)
	}
	if err != nil {
		log.Errorf("cannot set capturing server filter: %v", err)
	}

	// Create IP setter
	if configuration.DHCP.Enable {
		log.Infof("Creating the interface IP address handler")
		configuration.AddNet = make(chan net.IPNet, 100)
		configuration.RemoveNet = make(chan net.IPNet, 100)
		configuration.StopNet = make(chan int)
		configuration.Cache, err = lru.NewWithEvict(configuration.MaxDevices, func(key interface{}, value interface{}){
			if value != nil {
				device := value.(base.Device)
				if device.DHCP != nil && device.DHCP.ServerIP != nil {
					configuration.RemoveNet <- net.IPNet{IP: *device.DHCP.ServerIP, Mask: *device.DHCP.NetworkMask}
				}
			}
		})
		if err != nil {
			log.Errorf("cannot create device cache: %v", err)
			return configuration, errors.New("cannot create device cache")
		}
		go configuration.LocalAddressManager(configuration.AddNet, configuration.RemoveNet, configuration.StopNet)
	} else {
		configuration.Cache, err = lru.New(configuration.MaxDevices)
		if err != nil {
			log.Debugf("cannot create device cache: %v", err)
			return configuration, errors.New("cannot create device cache")
		}
	}

	return configuration, nil
}

func main() {
	log.SetOutput(os.Stderr)
	cfg := Config{}

	configurator := &easyconfig.Configurator{
		ProgramName: "provision",
	}

	easyconfig.ParseFatal(configurator, &cfg)
	log.Debugf("Started with %#v", cfg)
	service.Main(&service.Info{
		Name: "riprovisioner",
		AllowRoot:true,
		NewFunc: func() (service.Runnable, error) {
			return New(cfg)
		},
	})
}

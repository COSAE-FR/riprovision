package main

import (
	"errors"
	"fmt"
	"github.com/gcrahay/riprovision/base"
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
	if len(errs) > 0 {
		log.Printf("Found %d error(s) loading the config file:", len(errs))
		for i, e := range errs {
			log.Printf("Error %d: %s", i, e.Error())
		}
		return configuration, errors.New("errors when parsing config file")
	}

	// Create capturing server
	log.Printf("Starting capturing server on interface %s", configuration.Interface)
	configuration.Handler, err = base.New(configuration.Iface)
	if err != nil {
		return configuration, fmt.Errorf("cannot bind to interface %s", configuration.Interface)
	}
	log.Printf("Capturing server started")
	if configuration.DHCP.Enable {
		log.Printf("Setting capturing filter: %s", GlobalFilter)
		err = configuration.Handler.SetFilter(GlobalFilter)
	} else {
		log.Printf("Setting capturing filter: %s", NoDHCPFilter)
		err = configuration.Handler.SetFilter(NoDHCPFilter)
	}
	if err != nil {
		log.Printf("cannot set capturing server filter: %v", err)
	}

	// Create IP setter
	if configuration.DHCP.Enable {
		configuration.AddNet = make(chan net.IPNet, 100)
		configuration.RemoveNet = make(chan net.IPNet, 100)
		configuration.StopNet = make(chan int)
		go configuration.LocalAddressManager(configuration.AddNet, configuration.RemoveNet, configuration.StopNet)
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
	log.Printf("Started with %#v", cfg)
	service.Main(&service.Info{
		Name: "riprovisioner",

		NewFunc: func() (service.Runnable, error) {
			return New(cfg)
		},
	})
}

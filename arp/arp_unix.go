// +build !linux,!windows

// only tested on OSX
// decided to go with exec.Command after I couldn't figure
// out how to extract the arp cache out of the kernel with
// golang's syscall or Sysctl()
//
// ... Help appreciated :)

package arp

import (
	"os/exec"
	"strings"
)

const (
	f_Question int = iota
	f_IPAddr
	f_At
	f_HWAddr
	f_On
	f_Device
	f_Expiration
)

func Table() ArpTable {
	data, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return nil
	}

	var table = make(ArpTable)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// strip brackets around IP
		ip := strings.Replace(fields[f_IPAddr], "(", "", -1)
		ip = strings.Replace(ip, ")", "", -1)

		permanent := fields[f_Expiration] == "permanent"

		// Prefer first permanent entries
		previous, found := table[ip]
		if found && previous.Permanent {
			continue
		}

		table[ip] = ArpEntry{fields[f_HWAddr], ip, fields[f_Device], permanent}
	}

	return table
}

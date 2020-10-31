package base

import (
	"bytes"
	"errors"
	"fmt"
	pssh "github.com/COSAE-FR/riprovision/ssh"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"text/template"
	"time"
)

const defaultConfigurationBin = "/usr/bin/cfgmtd"
const defaultRebootBin = "/usr/bin/reboot"

// IsBusy states whether or not this Device is ready to receive commands.
func (d *Device) IsBusy() bool {
	d.busyMtx.RLock()
	defer d.busyMtx.RUnlock()
	return d.busy
}

func (d *Device) setBusy(msg string) error {
	d.busyMtx.Lock()
	defer d.busyMtx.Unlock()
	if d.busy {
		return fmt.Errorf("Device is busy (%s)", d.busyMsg)
	}
	d.busy = true
	d.busyMsg = msg
	return nil
}

func (device *Device) generateConfiguration() (conf string, err error) {
	logger := device.Log.WithField("component", "device_configuration")
	if !device.IsReady() {
		return "", errors.New("device is not ready")
	}
	var buf bytes.Buffer
	modelTmpl, found := device.Unifi.Provision.Configuration.Models[device.Unifi.Model]
	if !found {
		logger.Errorf("Cannot find configurator template name for device model: %s", device.Unifi.Model)
		err = errors.New("cannot find configurator template name for device")
		return
	}
	tmplString, found := device.Unifi.Provision.Configuration.Templates[modelTmpl]
	if found == false {
		logger.Errorf("Cannot find configurator template for device model: %s", device.Unifi.Model)
		err = errors.New("cannot find configurator template for device")
		return
	}
	tmpl, err := template.New("device_configuration").Parse(tmplString)
	if err != nil {
		logger.Errorf("Cannot parse configurator template for device model: %s, %v", device.Unifi.Model, err)
		return
	}
	err = tmpl.Execute(&buf, device)
	if err != nil {
		logger.Errorf("Cannot execute configurator template for device model: %s, %v", device.Unifi.Model, err)
		return
	}
	conf = buf.String()
	return
}

func (d *Device) IsReady() bool {
	if d.Unifi != nil && d.Unifi.Provision != nil {
		provision := d.Unifi.Provision
		if len(provision.Iface) > 0 && provision.IP != nil && provision.Mask != nil {
			if len(d.Unifi.Model) > 0 {
				return true
			}
		}
	}
	return false
}

// Provision updates the system config on the remote device.
func (d *Device) Provision() error {
	if !d.IsReady() {
		return errors.New("device is not ready")
	}
	if d.Unifi.Provision.IP.String() == "" {
		return errors.New("device has no IP address, cannot provision")
	}
	return d.withSSHClient("provisioning", d.doProvision)
}

func getBinaryPaths(c *ssh.Client, name string) (error, []string) {
	var paths string
	findCommand := fmt.Sprintf("find / -name \"%s\"", name)
	paths, sessionError := pssh.ExecuteCommand(c, findCommand)
	if sessionError != nil {
		return sessionError, nil
	}
	return nil, strings.Split(paths, "\n")
}

func runCommand(c *ssh.Client, logger *logrus.Entry, name string, defaultName string, line string) error {
	err, paths := getBinaryPaths(c, name)
	if err != nil {
		if len(defaultName) > 0 {
			logger.Errorf("Could not find %s binary: %v, trying default path %s", name, err, defaultName)
		} else {
			return fmt.Errorf("cannot find binary %s", name)
		}

	}
	if paths == nil || len(paths) == 0 {
		paths = []string{defaultName}
	}

	configured := false
	for _, binary := range paths {
		command := binary
		if len(line) > 0 {
			command = fmt.Sprintf(line, binary)
		}
		logger.Infof("Trying to run: %s", command)
		_, sessionError := pssh.ExecuteCommand(c, command)
		if sessionError != nil {
			logger.Errorf("Could not run %s: %v", command, sessionError)
			continue
		}
		configured = true
		break
	}

	if !configured {
		return fmt.Errorf("no working %s binary", name)
	}
	return nil
}

// runs in background-goroutine
func (d *Device) doProvision(c *ssh.Client) {
	logger := d.Log.WithField("component", "device_provision")
	logger.Debug("Start provisioning...")
	var sessionError error

	tmpfile, err := ioutil.TempFile("", "device_configuration")
	if err != nil {
		logger.Errorf("Cannot create temporary configurator file: %v", err)
		return
	}

	defer os.Remove(tmpfile.Name()) // clean up

	configurationString, err := d.generateConfiguration()
	if err != nil {
		logger.Errorf("Cannot generate configurator: %v", err)
		return
	}

	content := []byte(configurationString)

	if _, err := tmpfile.Write(content); err != nil {
		logger.Errorf("Cannot write temporary configurator file: %v", err)
		return
	}
	if err := tmpfile.Close(); err != nil {
		logger.Errorf("Cannot close temporary configurator file: %v", err)
		return
	}

	remotePath := "/tmp/system.cfg"
	if sessionError = pssh.UploadFile(c, tmpfile.Name(), remotePath); sessionError != nil {
		logger.Errorf("Upload failed: %v", sessionError)
		return
	}
	logger.Debugf("local(%s) -> remote(%s) 100%%", tmpfile.Name(), remotePath)

	err = runCommand(c, logger, "cfgmtd", defaultConfigurationBin, "%s -w -p /etc/")
	if err != nil {
		logger.Errorf("Could not find cfgmtd binary: %v, trying default path %s", err, defaultConfigurationBin)
		return
	}

	logger.Info("Configuration saved")

	err = runCommand(c, logger, "reboot", defaultRebootBin, "")
	if err == nil {
		d.markReboot(5 * time.Second)
		logger.Info("Reboot succeeded")
	} else {
		logger.Errorf("Cannot reboot: %v", err)
	}
}

// Reboot issues a reboot on the device.
func (d *Device) Reboot() error {
	logger := d.Log.WithField("component", "device_reboot")
	return d.withSSHClient("rebooting", func(c *ssh.Client) {
		err := runCommand(c, logger, "reboot", defaultRebootBin, "")
		if err == nil {
			d.markReboot(5 * time.Second)
			logger.Info("Reboot succeeded")
		} else {
			logger.Error("Cannot reboot device, no working binary found")
		}

	})
}

func (d *Device) withSSHClient(msg string, callback func(*ssh.Client)) error {
	logger := d.Log.WithField("component", "device_ssh")
	var client *ssh.Client
	if err := d.setBusy(msg); err != nil {
		return err
	}

	for _, user := range d.Unifi.Provision.Configuration.SSH.Usernames {
		client = d.getSSHClient(user)
		if client != nil {
			break
		}
		logger.Errorf("Could not obtain SSH client for user %s", user)
	}

	if client == nil {
		d.busy = false
		return fmt.Errorf("could not obtain SSH client")
	}

	logger.Debug("Got a client")

	go func() {
		callback(client)
		logger.Info("Callback succeeded")
		d.busy = false
		_ = client.Close()
	}()

	return nil
}

func (d *Device) getSSHClient(user string) *ssh.Client {
	clientConfig := &ssh.ClientConfig{
		Timeout:         2 * time.Second,
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	for i, m := range d.Unifi.Provision.Configuration.SSH.sshAuthMethods {
		clientConfig.Auth = []ssh.AuthMethod{m}
		authType := reflect.TypeOf(m).String()

		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", d.DHCP.ClientIP.String()), clientConfig)
		if err != nil {
			d.Log.Errorf("(try %d) %s authentication failed with %v", i+1, authType, err)
			continue
		}

		d.Log.Infof("(try %d) %s authentication succeeded", i+1, authType)
		return client
	}

	return nil
}

// markReboot sets the RebootedAt flat to a time in the future. This is
// used to detect reboot cycles, which may not be effective immediately,
// and hence makes the device misleadingly available/idle in the UI.
func (d *Device) markReboot(inFuture time.Duration) {
	d.Unifi.RebootedAt = time.Now().Add(inFuture)
}

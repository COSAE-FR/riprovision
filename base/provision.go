package base

import (
	"bytes"
	"errors"
	"fmt"
	pssh "github.com/gcrahay/riprovision/ssh"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"reflect"
	"text/template"
	"time"
)

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
	if !device.IsReady() {
		return "", errors.New("device is not ready")
	}
	var buf bytes.Buffer
	modelTmpl, found := device.Unifi.Provision.Configuration.Models[device.Unifi.Model]
	if !found {
		device.Log.Errorf("Cannot find configurator template name for device model: %s", device.Unifi.Model)
		err = errors.New("cannot find configurator template name for device")
		return
	}
	tmplString, found := device.Unifi.Provision.Configuration.Templates[modelTmpl]
	if found == false {
		device.Log.Errorf("Cannot find configurator template for device model: %s", device.Unifi.Model)
		err = errors.New("cannot find configurator template for device")
		return
	}
	tmpl, err := template.New("device_configuration").Parse(tmplString)
	if err != nil {
		device.Log.Errorf("Cannot parse configurator template for device model: %s, %v", device.Unifi.Model, err)
		return
	}
	err = tmpl.Execute(&buf, device)
	if err != nil {
		device.Log.Errorf("Cannot execute configurator template for device model: %s, %v", device.Unifi.Model, err)
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

// runs in background-goroutine
func (d *Device) doProvision(c *ssh.Client) {
	d.Log.Debug("Start provisioning...")
	var sessionError error

	tmpfile, err := ioutil.TempFile("", "device_configuration")
	if err != nil {
		d.Log.Errorf("Cannot create temporary configurator file: %v", err)
		return
	}

	defer os.Remove(tmpfile.Name()) // clean up

	configurationString, err := d.generateConfiguration()
	if err != nil {
		d.Log.Errorf("Cannot generate configurator: %v", err)
		return
	}

	content := []byte(configurationString)

	if _, err := tmpfile.Write(content); err != nil {
		d.Log.Errorf("Cannot write temporary configurator file: %v", err)
		return
	}
	if err := tmpfile.Close(); err != nil {
		d.Log.Errorf("Cannot close temporary configurator file: %v", err)
		return
	}

	remotePath := "/tmp/system.cfg"
	var output string
	if sessionError = pssh.UploadFile(c, tmpfile.Name(), remotePath); sessionError != nil {
		d.Log.Errorf("Upload failed: %v", sessionError)
		return
	}
	d.Log.Debugf("local(%s) -> remote(%s) 100%%", tmpfile.Name(), remotePath)

	output, sessionError = pssh.ExecuteCommand(c, "/usr/bin/cfgmtd -w -p /etc/")
	if sessionError != nil {
		d.Log.Errorf("Could not save configurator: %v", sessionError)
		return
	}
	d.Log.Infof("Configuration saved: %s", output)

	output, sessionError = pssh.ExecuteCommand(c, "/usr/bin/reboot")
	if sessionError != nil {
		d.Log.Errorf("Reboot failed: %v", sessionError)
		return
	}
	d.markReboot(5 * time.Second)
	d.Log.Infof("Reboot succeeded: %s", output)
}

// Reboot issues a reboot on the device.
func (d *Device) Reboot() error {
	return d.withSSHClient("rebooting", func(c *ssh.Client) {
		out, sessionError := pssh.ExecuteCommand(c, "/usr/bin/reboot")
		if sessionError != nil {
			d.Log.Errorf("Reboot failed: %v", sessionError)
			return
		}
		d.markReboot(5 * time.Second)
		d.Log.Infof("Reboot succeeded: %s", out)
	})
}

func (d *Device) withSSHClient(msg string, callback func(*ssh.Client)) error {
	var client *ssh.Client
	if err := d.setBusy(msg); err != nil {
		return err
	}

	for _, user := range d.Unifi.Provision.Configuration.SSH.Usernames {
		client = d.getSSHClient(user)
		if client != nil {
			break
		}
		d.Log.Errorf("Could not obtain SSH client for user %s", user)
	}

	if client == nil {
		d.busy = false
		return fmt.Errorf("Could not obtain SSH client")
	}

	d.Log.Debug("Got a client")

	go func() {
		callback(client)
		d.Log.Info("Callback succeeded")
		d.busy = false
		client.Close()
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

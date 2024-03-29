package ssh

import (
	"bytes"
	"crypto/x509"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"encoding/pem"

	"strings"

	"github.com/digineo/goldflags"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type sshSessionCallback func(*ssh.Session) error

// Agent tries to connect with the ssh-agent
func Agent() ssh.AuthMethod {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_agent",
	})
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		logger.Warn("SSH_AUTH_SOCK is not defined or empty")
		return nil
	}

	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err == nil {
		logger.Warnf("Couldn't connect to SSH agent: %v", err)
		return nil
	}

	localAgent := agent.NewClient(sshAgent)
	keys, err := localAgent.List()
	if err != nil {
		logger.Warnf("Listing keys error'ed: %v", err)
	} else {
		logger.Debugf("Keys: %v", keys)
	}
	return ssh.PublicKeysCallback(localAgent.Signers)
}

// ReadPrivateKey tries to read an SSH private key file.
func ReadPrivateKey(keyPath, password string) (auth ssh.AuthMethod, ok bool) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_keyfile",
	})
	keyFile, err := goldflags.ExpandPath(keyPath)
	if err != nil {
		logger.Warnf("Could not expand %s: %v", keyPath, err)
		return
	}

	if !goldflags.PathExist(keyFile) {
		logger.Warnf(" Keyfile %s not found", keyFile)
		return
	}

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		logger.Warnf("Could not read %s: %v", keyFile, err)
		return
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		log.Printf("[ssh.ReadPrivateKey] No key found in %s", keyFile)
		return
	}

	keyFrom := block.Bytes
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		keyFrom, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			logger.Warnf("Error decrypting %s: %v", keyFile, err)
			return
		}
	}

	key, err := getKey(block.Type, keyFrom)
	if err != nil {
		logger.Warnf("Cannot get key %s: %v", keyFile, err)
		return
	}

	sign, err := ssh.NewSignerFromKey(key)
	if err != nil {
		logger.Warnf("Cannot get signer %s: %v", keyFile, err)
		return
	}
	return ssh.PublicKeys(sign), true
}

func getKey(typ string, b []byte) (interface{}, error) {
	switch typ {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(b)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(b)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(b)
	case "DSA PRIVATE KEY":
		return ssh.ParseDSAPrivateKey(b)
	default:
		return nil, fmt.Errorf("unsupported key type %q", typ)
	}
}

// WithinSession executes a callback function within a new SSH session of
// the given client.
func WithinSession(client *ssh.Client, callback sshSessionCallback) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	return callback(session)
}

// UploadFile uploads a local file to the remote. Please avoid funky
// remote file names, since there's no protection against command injection
func UploadFile(client *ssh.Client, localName string, remoteName string) error {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_upload",
		"src_file":  localName,
		"dest_file": remoteName,
	})
	binaries, _ := FindBinary(client, "scp")
	binaries = append(binaries, "/usr/bin/scp", "/usr/sbin/scp")
	return WithinSession(client, func(s *ssh.Session) error {
		writer, err := s.StdinPipe()
		if err != nil {
			return err
		}
		defer writer.Close()

		buf, err := ioutil.ReadFile(localName)
		if err != nil {
			return err
		}
		logger.Debugf("Local-file: %s, %d bytes", localName, len(buf))

		rdir := filepath.Dir(remoteName)
		logger.Debugf("Remote-dir: %s", rdir)

		rfile := filepath.Base(remoteName)
		logger.Debugf("Remote-file]: %s", rfile)

		var so, se bytes.Buffer
		s.Stdout = &so
		s.Stderr = &se

		var startError error
		for _, binary := range binaries {
			startError = nil
			cmd := fmt.Sprintf("%s -t %s", binary, rdir) // danger!
			logger.Debugf("Command: %s", cmd)
			if startError = s.Start(cmd); startError != nil {
				logger.Debugf("Cannot start scp: %s", startError)
				continue
			}
			break
		}
		if startError != nil {
			return startError
		}

		content := string(buf)
		logger.Debugf("Uploading: %d bytes", len(content))

		// https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works
		fmt.Fprintln(writer, "C0644", len(content), rfile)
		fmt.Fprint(writer, content)
		fmt.Fprint(writer, "\x00")
		writer.Close()

		if err := s.Wait(); err != nil {
			logger.Errorf("Waiting failed: %v", err)
			logger.Debugf("Stdout: %s, stdOut: %s", se.String(), so.String())
			return err
		}

		return nil
	})
}

// ExecuteCommand executes a command in a new SSH session.
func ExecuteCommand(client *ssh.Client, cmd string) (string, error) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_command",
		"command":   cmd,
	})
	var output string
	sessionErr := WithinSession(client, func(s *ssh.Session) error {
		var so, se bytes.Buffer
		s.Stdout = &so
		s.Stderr = &se

		if err := s.Run(cmd); err != nil {
			logger.Errorf("Command failed: %v", err)
			logger.Debugf("Stdout: %s, stdOut: %s", se.String(), so.String())
			return err
		}

		output = so.String()
		return nil
	})

	return output, sessionErr
}

// FindBinary searches the SSH target for a suitable binary
func FindBinary(client *ssh.Client, binary string) ([]string, error) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_find",
		"binary":    binary,
	})
	var paths string
	findCommand := fmt.Sprintf("find / -name \"%s\" -xdev -perm +700", binary)
	paths, sessionError := ExecuteCommand(client, findCommand)
	if sessionError != nil {
		logger.Errorf("Cannot find binaries: %s", sessionError)
		return nil, sessionError
	}
	binaries := make([]string, 0)
	for _, b := range strings.Split(paths, "\n") {
		if len(b) > 0 {
			binaries = append(binaries, b)
		}
	}
	return binaries, nil
}

// FindAndExecuteCommand finds a suitable binary on the SSH target and executes it
func FindAndExecuteCommand(client *ssh.Client, binary string, cmd string, defaultsPaths ...string) (string, error) {
	logger := log.WithFields(log.Fields{
		"app":       "riprovision",
		"component": "ssh_command_find",
		"binary":    binary,
		"command":   cmd,
	})
	binaries, findError := FindBinary(client, binary)
	if findError != nil {
		logger.Debugf("Cannot find binary, trying default path")
	}
	binaries = append(binaries, defaultsPaths...)
	for _, exe := range binaries {
		command := exe
		if len(cmd) > 0 {
			command = fmt.Sprintf(cmd, command)
		}
		logger.Debugf("Trying to run '%s'", command)
		output, err := ExecuteCommand(client, command)
		if err != nil {
			logger.Errorf("Cannot run '%s': %s", command, err)
			continue
		}
		return output, nil
	}
	logger.Debug("Cannot find suitable binary")
	return "", fmt.Errorf("no suitable binary or command error")
}

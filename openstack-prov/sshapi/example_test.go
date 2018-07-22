package sshapi

import (
	"fmt"
	"github.com/nanobox-io/golang-ssh"
	"os"
	"testing"
)

var testTarget = "" //TODO use FQDN reserved for testing

func TestSSH(t *testing.T) {
	//auth := ssh.Auth{Passwords: []string{"pass"}}

	home := os.Getenv("HOME")
	testTarget = os.Getenv("SSH_TEST_TARGET")
	auth := ssh.Auth{Keys: []string{home + "/.ssh/id_rsa_mobiledgex"}}
	client, err := ssh.NewNativeClient("mobiledgex", testTarget, "SSH-2.0-mobiledgex-ssh-client-1.0", 22, &auth, nil)
	if err != nil {
		t.Error(err)
		return
	}

	err = client.Shell("cat", "/etc/hosts")
	if err != nil && err.Error() != "exit status 255" {
		t.Error(err)
		return
	}

	out, err := client.Output("ps ax | grep docker")
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(out)
}

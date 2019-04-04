package sshapi

import (
	"fmt"
	"os"

	"github.com/nanobox-io/golang-ssh"
)

var mexTestInfra = os.Getenv("MEX_TEST_INFRA")

var testTarget = "" //TODO use FQDN reserved for testing

func main() {
	if mexTestInfra == "" {
		return
	}
	//auth := ssh.Auth{Passwords: []string{"pass"}}

	home := os.Getenv("HOME")
	testTarget = os.Getenv("SSH_TEST_TARGET")
	auth := ssh.Auth{Keys: []string{home + "/.ssh/id_rsa_mobiledgex"}}
	client, err := ssh.NewNativeClient("mobiledgex", testTarget, "SSH-2.0-mobiledgex-ssh-client-1.0", 22, &auth, nil)
	if err != nil {
		panic(err)
	}

	err = client.Shell("cat", "/etc/hosts")
	if err != nil && err.Error() != "exit status 255" {
		panic(err)
	}

	out, err := client.Output("ps ax | grep docker")
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}

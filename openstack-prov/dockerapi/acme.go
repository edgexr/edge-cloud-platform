package mexdocker

import (
	"os"
	"time"

	"github.com/fsouza/go-dockerclient"
)

//GetCertificate obtains certificate and key from Letsencrypt via acme.sh container
//  XXX Letsencrypt throttles API calls per week.  Do not run this too often!
//  This requires environement variables CF_USER and CF_KEY.
//  The values for CF_KEY and CF_USER can be obtained from Cloudflare account.
func GetCertificate(dn string) error {
	//hn, err := os.Hostname()
	//if err != nil {
	//	t.Errorf("can't get hostname, %v", err)
	//	return
	//}
	var err error

	home := os.Getenv("HOME")
	certDir := home + "/.mobiledgex/certs"
	_, err = os.Stat(certDir)
	if err != nil {
		err = os.MkdirAll(certDir, 0666)
		if err != nil {
			return err
		}
	}

	_, err = os.Stat(certDir + "/" + dn)
	if err != nil {
		return RunACME(dn, certDir)
	}

	return nil
}

//RunACME creates a docker instance of acme.sh to obtain certs
func RunACME(dn, certDir string) error {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		return err
	}

	config := &docker.Config{}
	config.AttachStdin = true
	config.AttachStdout = true
	config.AttachStderr = true
	config.Tty = true
	config.Cmd = []string{}
	config.Env = []string{}

	netConfig := &docker.NetworkingConfig{}

	hostConfig := &docker.HostConfig{}
	hostConfig.NetworkMode = "host"
	hostConfig.AutoRemove = true

	// create acme.sh container to get the certificate and key for this host
	config.Image = "neilpang/acme.sh"
	cfuser := os.Getenv("CF_USER")
	cfkey := os.Getenv("CF_KEY")
	config.Env = []string{"CF_Key=" + cfkey, "CF_Email=" + cfuser}
	config.Cmd = []string{"--issue", "-d", dn, "--dns", "dns_cf"}
	hostConfig.Binds = []string{certDir + ":/acme.sh"}

	opts := docker.CreateContainerOptions{Name: "acme.sh", Config: config, NetworkingConfig: netConfig, HostConfig: hostConfig}
	container, err := client.CreateContainer(opts)
	if err != nil {
		return err
	}

	err = client.StartContainer(container.ID, nil)
	if err != nil {
		return err
	}

	for {
		_, err := os.Stat(certDir + "/" + dn + "/fullchain.cer")
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(10 * time.Second)
	}

	err = client.StopContainer(container.ID, 1)
	if err != nil {
		return err
	}

	return nil
}

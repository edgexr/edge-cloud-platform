package mexdocker

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fsouza/go-dockerclient"
)

func TestListContainers(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}
	cl, err := client.ListContainers(docker.ListContainersOptions{All: true})
	if err != nil {
		t.Error(err)
		return
	}
	for _, c := range cl {
		fmt.Println(c)
	}
}

func TestListImages(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}
	imgs, err := client.ListImages(docker.ListImagesOptions{All: false})
	if err != nil {
		t.Error(err)
		return
	}
	for _, img := range imgs {
		fmt.Println("ID: ", img.ID)
		fmt.Println("RepoTags: ", img.RepoTags)
		fmt.Println("Created: ", img.Created)
		fmt.Println("Size: ", img.Size)
		fmt.Println("VirtualSize: ", img.VirtualSize)
		fmt.Println("ParentId: ", img.ParentID)
	}
}

var containerID = ""

var containerImage = "mobiledgex/mexosagent"
var containerName = "mexosagent"

func TestCreateContainer(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}

	config := &docker.Config{}
	config.AttachStdin = true
	config.AttachStdout = true
	config.AttachStderr = true
	config.Tty = true
	config.OpenStdin = true
	config.Cmd = []string{"--issue", "-d", "yourdomain.gq", "--dns", "dns_cf"}

	cfEmail := os.Getenv("CF_USER")
	cfKey := os.Getenv("CF_KEY")

	config.Env = []string{"CF_Email=" + cfEmail, "CF_Key=" + cfKey}

	netConfig := &docker.NetworkingConfig{}

	hostConfig := &docker.HostConfig{}
	hostConfig.NetworkMode = "host"
	hostConfig.AutoRemove = true

	//config.Image = "mobiledgex/mexosagent"
	config.Image = containerImage

	home := os.Getenv("HOME")
	certDir := home + "/.mobiledgex/certs" //+ FQDN

	hostConfig.Binds = []string{certDir + ":/var/www/.cache", "/etc/ssl/certs:/etc/ssl/certs"}

	opts := docker.CreateContainerOptions{Name: containerName, Config: config, NetworkingConfig: netConfig, HostConfig: hostConfig}
	container, err := client.CreateContainer(opts)
	if err != nil {
		t.Error(err)
		return
	}

	containerID = container.ID

	fmt.Println("created container", containerID, container)
}

func TestStartContainer(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}

	if containerID != "" {
		err = client.StartContainer(containerID, nil)
		if err != nil {
			t.Error(err)
			return
		}
	} else {
		cl, err := client.ListContainers(docker.ListContainersOptions{All: true})
		if err != nil {
			t.Error(err)
			return
		}

		for _, c := range cl {
			for _, n := range c.Names {
				if strings.Index(n, containerName) >= 0 {
					fmt.Println("starting ", n)
					err = client.StartContainer(c.ID, nil)
					if err != nil {
						t.Error(err)
						return
					}
				}
			}
		}
	}

	fmt.Println("started container", containerID)
}

func TestStopContainer(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}

	err = client.StopContainer(containerID, 1)
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println("stopped container", containerID)
}

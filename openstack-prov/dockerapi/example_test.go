package dockerapi

import (
	"fmt"
	"testing"

	"github.com/fsouza/go-dockerclient"
)

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
	config.Image = "busybox"
	config.Cmd = []string{"sh"}

	netConfig := &docker.NetworkingConfig{}

	hostConfig := &docker.HostConfig{}
	hostConfig.AutoRemove = true

	opts := docker.CreateContainerOptions{Config: config, NetworkingConfig: netConfig, HostConfig: hostConfig}
	container, err := client.CreateContainer(opts)
	if err != nil {
		t.Error(err)
		return
	}

	containerID = container.ID

	fmt.Println("created container", container)
}

func TestStartContainer(t *testing.T) {
	client, err := docker.NewClientFromEnv()
	if err != nil {
		t.Error(err)
		return
	}

	err = client.StartContainer(containerID, nil)
	if err != nil {
		t.Error(err)
		return
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

package gcloud

import (
	"fmt"

	"github.com/codeskyblue/go-sh"
)

func SetProject(project string) error {
	out, err := sh.Command("gcloud", "config", "set", "project", project).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func SetZone(zone string) error {
	out, err := sh.Command("gcloud", "config", "set", "compute/zone", zone).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func CreateGKECluster(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "create", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func GetGKECredentials(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "get-credentials", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func DeleteGKECluster(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "delete", "--quiet", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

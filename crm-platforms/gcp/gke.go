package gcp

import (
	"fmt"

	"github.com/codeskyblue/go-sh"
)

//SetProject sets the project in gcloud config
func SetProject(project string) error {
	out, err := sh.Command("gcloud", "config", "set", "project", project).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//SetZone sets the zone in gcloud config
func SetZone(zone string) error {
	out, err := sh.Command("gcloud", "config", "set", "compute/zone", zone).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//CreateGKECluster creates a kubernetes cluster on gcloud
func CreateGKECluster(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "create", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//GetGKECredentials retrieves kubeconfig credentials from gcloud. Often this retrieves wrong x509 certs. This
//  may require you to use `--insecure-skip-tls-verify=true` to `kubectl`
func GetGKECredentials(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "get-credentials", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//DeleteGKECluster removes kubernetes cluster on gcloud
func DeleteGKECluster(name string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "delete", "--quiet", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

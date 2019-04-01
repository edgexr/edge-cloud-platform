package azure

import (
	"fmt"

	"github.com/codeskyblue/go-sh"
)

//CreateResourceGroup creates azure resource group
func CreateResourceGroup(group, location string) error {
	out, err := sh.Command("az", "group", "create", "-l", location, "-n", group).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//CreateAKSCluster creates kubernetes cluster on azure
func CreateAKSCluster(group, name, vm_size, num_nodes string) error {
	out, err := sh.Command("az", "aks", "create", "--resource-group", group,
		"--name", name, "--generate-ssh-keys",
		"--node-vm-size", vm_size,
		"--node-count", num_nodes).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//GetAKSCredentials retrieves kubeconfig credentials from azure for the cluster just created
func GetAKSCredentials(group, name string) error {
	out, err := sh.Command("az", "aks", "get-credentials", "--resource-group", group, "--name", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

//DeleteAKSCluster removes the kubernetes cluster on azure
func DeleteAKSCluster(group string) error {
	out, err := sh.Command("az", "group", "delete", "--name", group, "--yes", "--no-wait").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

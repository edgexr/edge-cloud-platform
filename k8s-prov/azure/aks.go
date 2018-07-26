package azure

import (
	"fmt"

	"github.com/codeskyblue/go-sh"
)

func CreateResourceGroup(group, location string) error {
	out, err := sh.Command("az", "group", "create", "-l", location, "-n", group).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func CreateAKSCluster(group, name string) error {
	out, err := sh.Command("az", "aks", "create", "--resource-group", group, "--name", name, "--generate-ssh-keys").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func GetAKSCredentials(group, name string) error {
	out, err := sh.Command("az", "aks", "get-credentials", "--resource-group", group, "--name", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

func DeleteAKSCluster(group string) error {
	out, err := sh.Command("az", "group", "delete", "--name", group, "--yes", "--no-wait").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	return nil
}

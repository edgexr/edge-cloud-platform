package artifactory

import (
	"fmt"
	"os"
)

func GetCreds() (string, string, error) {
	af_user := os.Getenv("MEX_ARTIFACTORY_USER")
	if af_user == "" {
		return "", "", fmt.Errorf("Env variable MEX_ARTIFACTORY_USER not set")
	}
	af_pass := os.Getenv("MEX_ARTIFACTORY_PASS")
	if af_pass == "" {
		return "", "", fmt.Errorf("Env variable MEX_ARTIFACTORY_PASS not set")
	}
	return af_user, af_pass, nil
}

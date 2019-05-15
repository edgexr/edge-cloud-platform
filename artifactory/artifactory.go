package artifactory

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud/log"
)

func GetArtifactoryApiKey() (string, error) {
	artifactoryApiKey := os.Getenv("artifactory_apikey")
	if artifactoryApiKey == "" {
		log.InfoLog("Note: No 'artifactory_apikey' env var found")
		return "", fmt.Errorf("Artifactory API Key not found")
	}
	return artifactoryApiKey, nil
}

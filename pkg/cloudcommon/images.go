package cloudcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

type SkopeoInspectLayer struct {
	MIMEType string
	Digest   string
	Size     string
	// Annotations -> not sure what data type
}

type SkopeoInspect struct {
	Name          string
	Digest        string
	RepoTags      []string
	Created       time.Time
	DockerVersion string
	Labels        map[string]string
	Architecture  string
	Os            string
	Layers        []string
	LayersData    []SkopeoInspectLayer
	Env           []string
}

// Return sha256 image digest, requires skopeo installed
func GetDockerImageChecksum(ctx context.Context, imagePath string, auth *RegistryAuth) (string, error) {
	// shouldn't have leading scheme, strip it just in case
	imagePath = util.TrimScheme(imagePath)

	args := []string{"inspect"}
	if auth != nil && auth.AuthType == BasicAuth {
		args = append(args, "--creds", auth.Username+":"+auth.Password)
	}
	args = append(args, "docker://"+strings.ToLower(imagePath))
	cmd := exec.Command("skopeo", args...)
	logCmd := cmd.String()
	if auth != nil {
		logCmd = strings.ReplaceAll(cmd.String(), auth.Password, "xxx")
	}
	log.SpanLog(ctx, log.DebugLevelApi, "get docker image checksum", "cmd", logCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get docker image checksum failed, %s: %s, %s", logCmd, string(out), err)
	}
	data := SkopeoInspect{}
	err = json.Unmarshal(out, &data)
	if err != nil {
		return "", fmt.Errorf("get docker image checksum failed to unmarshal inspect output: %s", err)
	}
	return data.Digest, nil
}
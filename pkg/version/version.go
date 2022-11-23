package version

import (
	"context"
	"io/ioutil"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"gopkg.in/yaml.v2"
)

type BuildInfo struct {
	BuildTag    string `yaml:"buildtag"`
	BuildMaster string `yaml:"buildmaster"`
	BuildHead   string `yaml:"buildhead"`
	BuildAuthor string `yaml:"buildauthor"`
	BuildDate   string `yaml:"builddate"`
}

// GetBuildInfo from an external yaml file.
// This if for binaries distributed in containers, to
// avoid having the binaries change when other binary
// was modified which caused the build version to change.
// version.yaml is expected to be copied to the root
// of the container.
// For binaries distributed outside of containers, use
// versions from the version_embedded package.
func GetBuildInfo(ctx context.Context) *BuildInfo {
	info := &BuildInfo{}
	dat, err := ioutil.ReadFile("/version.yaml")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "BuildProps failed to read version.yaml", "err", err)
		return info
	}
	err = yaml.Unmarshal(dat, info)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "BuildProps failed to unmarshal version.yaml", "err", err)
		return info
	}
	return info
}

func BuildProps(ctx context.Context, prefix string) map[string]string {
	info := GetBuildInfo(ctx)
	m := map[string]string{
		prefix + "BuildTag":    info.BuildTag,
		prefix + "BuildMaster": info.BuildMaster,
		prefix + "BuildHead":   info.BuildHead,
		prefix + "BuildDate":   info.BuildDate,
	}
	if info.BuildAuthor != "" {
		m[prefix+"BuildAuthor"] = info.BuildAuthor
	}
	return m
}

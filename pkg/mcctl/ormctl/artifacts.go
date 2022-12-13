package ormctl

const ArtifactGroup = "Artifact"

func init() {
	cmds := []*ApiCommand{{
		Name:         "UploadArtifact",
		Use:          "upload",
		Short:        "Upload an artifact (img, iso, ova, tar, etc)",
		RequiredArgs: "org path localfile",
		Comments:     artifactComments,
	}, {
		Name:         "UploadArtifactFromURL",
		Use:          "uploadfromurl",
		Short:        "Upload an artifact from a remote URL",
		RequiredArgs: "org path remoteurl",
		OptionalArgs: "remoteusername remotepassword remotetoken",
		Comments:     artifactComments,
	}, {
		Name:         "InfoArtifact",
		Use:          "info",
		Short:        "Get artifact information",
		RequiredArgs: "org path",
		Comments:     artifactComments,
	}, {
		Name:         "DownloadArtifact",
		Use:          "download",
		Short:        "Download an artifact",
		RequiredArgs: "org path",
		OptionalArgs: "localfile",
		Comments:     artifactComments,
	}, {
		Name:         "ShowArtifacts",
		Use:          "show",
		Short:        "Show artifacts",
		RequiredArgs: "org",
		Comments:     artifactComments,
	}, {
		Name:         "DeleteArtifact",
		Use:          "delete",
		Short:        "Delete an artifact",
		RequiredArgs: "org path",
		Comments:     artifactComments,
	}}
	AllApis.AddGroup(ArtifactGroup, "Manage Artifacts", cmds)
}

var artifactComments = map[string]string{
	"org":            "Organization name",
	"path":           "Artifact file path on server, i.e. /path/to/my/file",
	"localfile":      "Local file path of artifact",
	"remoteurl":      "Remote URL to pull image from",
	"remoteusername": "Remote username for basic auth for uploading from URL",
	"remotepassword": "Remote password for basic auth for uploading from URL",
	"remotetoken":    "Remote token for bearer auth for uploading from URL",
}

package ormctl

const ArtifactGroup = "Artifact"

func init() {
	cmds := []*ApiCommand{{
		Name:         "UploadArtifact",
		Use:          "upload",
		Short:        "Ppload an artifact (img, iso, ova, tar, etc)",
		RequiredArgs: "org path localfile",
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
		Name:         "ListArtifacts",
		Use:          "list",
		Short:        "List artifacts",
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
	"org":       "Organization name",
	"path":      "Artifact file path on server, i.e. /path/to/my/file",
	"localfile": "Local file path of artifact",
}

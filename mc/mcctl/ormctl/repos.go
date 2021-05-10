package ormctl

const RepositoryGroup = "Repos"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:  "ArtifactoryResync",
		Short: "Resync MC and Artifactory data",
		Path:  "/auth/artifactory/resync",
	}, {
		Name:  "GitlabResync",
		Short: "Resync MC and Gitlab data",
		Path:  "/auth/gitlab/resync",
	}}
	AllApis.AddGroup(RepositoryGroup, "Manage respositories", cmds)
}

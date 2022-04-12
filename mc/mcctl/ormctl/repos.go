// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

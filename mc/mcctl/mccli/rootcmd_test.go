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

package mccli

import (
	"testing"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/test-go/testify/assert"
)

func TestGetRootCommand(t *testing.T) {
	// this will panic if any of the api cmd look ups are wrong
	GetRootCommand()

	// Validate all commands
	for _, cmd := range ormctl.AllApis.Commands {
		err := cmd.Validate()
		assert.Nil(t, err)
	}
}
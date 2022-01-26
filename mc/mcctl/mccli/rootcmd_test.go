package mccli

import (
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
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

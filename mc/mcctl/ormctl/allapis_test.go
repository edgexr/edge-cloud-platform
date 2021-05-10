package ormctl

import (
	fmt "fmt"
	"testing"
)

func TestInit(t *testing.T) {
	// empty test that just runs init()
	fmt.Printf("All commands count: %d\n", len(AllApis.Commands))
}

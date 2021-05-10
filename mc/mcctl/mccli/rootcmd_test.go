package mccli

import "testing"

func TestGetRootCommand(t *testing.T) {
	// this will panic if any of the api cmd look ups are wrong
	GetRootCommand()
}

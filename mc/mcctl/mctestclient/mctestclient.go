package mctestclient

import "github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"

type ClientRun interface {
	Run(apiCmd *ormctl.ApiCommand, runData *RunData)
	EnablePrintTransformations()
}

type RunData struct {
	Uri       string
	Token     string
	In        interface{}
	Out       interface{}
	RetStatus int
	RetError  error
}

type Client struct {
	ClientRun ClientRun
}

func NewClient(clientRun ClientRun) *Client {
	s := Client{}
	s.ClientRun = clientRun
	return &s
}

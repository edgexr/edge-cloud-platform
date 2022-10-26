package ormutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUriTemplate(t *testing.T) {
	values := map[string]string{
		"federationContextId": "fedctx21",
		"zoneId":              "ZoneFoo",
		"appId":               "123app",
		"appInstanceId":       "appInstfoo",
	}
	tests := []struct {
		in   string
		echo string
		eval string
	}{{
		"/partner/{federationContextId}",
		"/partner/:federationContextId",
		"/partner/fedctx21",
	}, {
		"{federationContextId}",
		":federationContextId",
		"fedctx21",
	}, {
		"{federationContextId}/zone",
		":federationContextId/zone",
		"fedctx21/zone",
	}, {
		"partner{federationContextId}/app/{appId}/zone{zoneId}",
		"partner:federationContextId/app/:appId/zone:zoneId",
		"partnerfedctx21/app/123app/zoneZoneFoo",
	}}
	for ii, test := range tests {
		ut := UriTemplate(test.in)
		eval := ut.Eval(values)
		require.Equal(t, test.eval, eval, "test eval %d %s", ii, test.in)
		echo := ut.EchoPath()
		require.Equal(t, test.echo, echo, "test echo %d %s", ii, test.in)

	}
}

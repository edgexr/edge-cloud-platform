package orm

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/stretchr/testify/require"
)

// Benchmarks to determine best way to clear sensitive data
// from request/response JSON data.

var jsonResponse = `{"ID":2,"Name":"enterprise-partner1","OperatorId":"enterprise","Regions":["local","locala"],"FederationContextId":"51d781ee4918498e8c94da75ea89a25b","MyInfo":{"FederationId":"enterprise-partner1085d364c07fb4fe0b09979127f7c3d68","CountryCode":"SA","MCC":"123","MNC":["111","222","333"],"FixedNetworkIds":["foo","bar","foobar"],"DiscoveryEndPoint":"","InitialDate":"0000-12-31T16:07:02-07:52"},"PartnerInfo":{"FederationId":"enterprise-partner1085d364c07fb4fe0b09979127f7c3d68","CountryCode":"SA","MCC":"456","MNC":["444","555","666"],"FixedNetworkIds":["blah","bloh","bluh"],"DiscoveryEndPoint":"","InitialDate":"2023-01-23T22:07:11.5983956-08:00"},"PartnerNotifyDest":"https://127.0.0.1:9808/operatorplatform/fedcallbacks/v1/onPartnerStatusEvent","PartnerNotifyTokenUrl":"https://127.0.0.1:9908/oauth2/token","PartnerNotifyClientId":"***","PartnerNotifyClientKey":"foobar","Status":"Registered","ProviderClientId":"9cbb1aef-b964-4e02-af9d-e3cd871fa054","CreatedAt":"2023-01-23T22:07:11.177071-08:00","UpdatedAt":"2023-01-23T22:07:11.6895558-08:00"}`

var keyStringRegex = regexp.MustCompile(`"PartnerNotifyClientKey":"(.+?)"`)
var keyStringRegexMiss = regexp.MustCompile(`"PartneNotifyClientKey":"(.+?)"`)
var keyReplace = `"PartnerNotifyClientKey":""`

// 1677 ns/op
func BenchmarkClearRegexp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		keyStringRegex.ReplaceAll([]byte(jsonResponse), []byte(keyReplace))
	}
}

// 1123 ns/op
func BenchmarkClearRegexpMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		keyStringRegexMiss.ReplaceAll([]byte(jsonResponse), []byte(keyReplace))
	}
}

// 1948 ns/op
func BenchmarkClearRegexpCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if strings.Contains(jsonResponse, "ClientKey") {
			keyStringRegex.ReplaceAll([]byte(jsonResponse), []byte(keyReplace))
		}
	}
}

// 18064 ns/op
func BenchmarkClearMarshal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if strings.Contains(jsonResponse, "ClientKey") {
			obj := ormapi.FederationProvider{}
			err := json.Unmarshal([]byte(jsonResponse), &obj)
			require.Nil(b, err)
			obj.PartnerNotifyClientKey = ""
			_, err = json.Marshal(&obj)
		}
	}
}

// 98 ns/op
func BenchmarkClearCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		strings.Contains(jsonResponse, "ClientKey")
	}
}

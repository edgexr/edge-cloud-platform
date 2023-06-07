package orm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/stretchr/testify/require"
)

// Benchmarks to determine best way to clear sensitive data
// from request/response JSON data.
// go test -bench=. -run=^#

var jsonResponse = `{"ID":2,"Name":"enterprise-partner1","OperatorId":"enterprise","Regions":["local","locala"],"FederationContextId":"51d781ee4918498e8c94da75ea89a25b","MyInfo":{"FederationId":"enterprise-partner1085d364c07fb4fe0b09979127f7c3d68","CountryCode":"SA","MCC":"123","MNC":["111","222","333"],"FixedNetworkIds":["foo","bar","foobar"],"DiscoveryEndPoint":"","InitialDate":"0000-12-31T16:07:02-07:52"},"PartnerInfo":{"FederationId":"enterprise-partner1085d364c07fb4fe0b09979127f7c3d68","CountryCode":"SA","MCC":"456","MNC":["444","555","666"],"FixedNetworkIds":["blah","bloh","bluh"],"DiscoveryEndPoint":"","InitialDate":"2023-01-23T22:07:11.5983956-08:00"},"PartnerNotifyDest":"https://127.0.0.1:9808/operatorplatform/fedcallbacks/v1/onPartnerStatusEvent","PartnerNotifyTokenUrl":"https://127.0.0.1:9908/oauth2/token","PartnerNotifyClientId":"***","PartnerNotifyClientKey":"foobar","Status":"Registered","ProviderClientId":"9cbb1aef-b964-4e02-af9d-e3cd871fa054","CreatedAt":"2023-01-23T22:07:11.177071-08:00","UpdatedAt":"2023-01-23T22:07:11.6895558-08:00"}`

// benchmark times from:
// Intel(R) Core(TM) i9-10850K CPU @ 3.60GHz

// 8303 ns/op (hit)
// 3007 ns/op (miss)
// BenchmarkClearRegexp removed. Although it was faster than
// unmarshal->marshal, it is slower than the parser and it is
// logically incorrect, unable to handle removing arrays, objects,
// and strings with escaped quotes.

// 3308 ns/op
func BenchmarkClearParser(b *testing.B) {
	for i := 0; i < b.N; i++ {
		redactor.Redact([]byte(jsonResponse))
	}
}

// 17064 ns/op
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

// 27060 ns/op
func BenchmarkClearMarshalGeneric(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if strings.Contains(jsonResponse, "ClientKey") {
			obj := make(map[string]interface{})
			err := json.Unmarshal([]byte(jsonResponse), &obj)
			require.Nil(b, err)
			lcKey := strings.ToLower("PartnerNotifyClientKey")
			for k, _ := range obj {
				if strings.ToLower(k) == lcKey {
					delete(obj, k)
				}
			}
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

type testRequestData struct {
	uri         string
	contentType string
	in          string
	exp         string
}

var testRequestDatas = []testRequestData{{
	// test password (applies to all requests), tests multiple secrets,
	// test case-insensitive json key
	uri:         "/api/v1/login",
	contentType: "application/json",
	in: `{
		"username": "myuser",
		"password": "mypass",
		"ToTp": "mytotp",
		"apikeyid": "myapikeyid",
		"apikey": "myapi\"key"
	  }`,
	exp: `{
		"username": "myuser",
		"password": "***",
		"ToTp": "***",
		"apikeyid": "myapikeyid",
		"apikey": "***"
	  }`,
}, {
	// test federation uri, test that unspecified fields are not
	// added in via object unmarshal->marshal
	uri:         "/api/v1/auth/federation/consumer/create",
	contentType: "application/json",
	in: `{
		"Name": "fedtest-guest",
		"OperatorId": "edgexr",
		"PartnerAddr": "https://console.cloud.edgexr.org",
		"PartnerTokenUrl": "https://console.cloud.edgexr.org/oauth2/token",
		"MyInfo": {
		  "CountryCode": "US",
		  "MCC": "123",
		  "MNC": [
			"123"
		  ],
		},
		"AutoRegisterZones": true,
		"AutoRegisterRegion": "US",
		"ProviderClientId": "providerclientid",
		"ProviderClientKey": "providerclientsecret",
	  }`,
	exp: `{
		"Name": "fedtest-guest",
		"OperatorId": "edgexr",
		"PartnerAddr": "https://console.cloud.edgexr.org",
		"PartnerTokenUrl": "https://console.cloud.edgexr.org/oauth2/token",
		"MyInfo": {
		  "CountryCode": "US",
		  "MCC": "123",
		  "MNC": [
			"123"
		  ],
		},
		"AutoRegisterZones": true,
		"AutoRegisterRegion": "US",
		"ProviderClientId": "providerclientid",
		"ProviderClientKey": "***",
	  }`,
}, {
	// test that non-string fields can be redacted:
	// access_vars and driver_path_creds
	uri:         "/api/v1/auth/ctrl/CreateCloudlet",
	contentType: "application/json",
	in: `  {
		"Region": "EU",
		"Cloudlet": {
		  "key": {
			"organization": "op",
			"name": "cloudlet1"
		  },
		  "location": {
			"latitude": 5,
			"longitude": 5
		  },
		  "ip_support": "Dynamic",
		  "num_dynamic_ips": 20,
		  "infra_api_access": "RestrictedAccess",
		  "infra_config": {
			"external_network_name": "foo",
			"flavor_name": "m4.small"
		  },
		  "access_vars": {
			"key1": "value1",
			"key2": "value2"
		  },
		  "gpu_config": {
			"license_config": "license_config_secret"
		  },
		}
	  }`,
	exp: `  {
		"Region": "EU",
		"Cloudlet": {
		  "key": {
			"organization": "op",
			"name": "cloudlet1"
		  },
		  "location": {
			"latitude": 5,
			"longitude": 5
		  },
		  "ip_support": "Dynamic",
		  "num_dynamic_ips": 20,
		  "infra_api_access": "RestrictedAccess",
		  "infra_config": {
			"external_network_name": "foo",
			"flavor_name": "m4.small"
		  },
		  "access_vars": "***",
		  "gpu_config": {
			"license_config": "***"
		  },
		}
	  }`,
}}

func TestRedactRequestSecrets(t *testing.T) {
	for _, test := range testRequestDatas {
		out, err := redactor.Redact([]byte(test.in))
		require.Nil(t, err)
		require.Equal(t, string(test.exp), string(out))
	}
}

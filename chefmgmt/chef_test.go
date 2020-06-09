package chefmgmt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChefArgs(t *testing.T) {
	cmdArgs := []string{
		"--notifyAddrs",
		"127.0.0.1:8080",
		"--platform",
		"openstack",
		"-testMode",
		"-cleanupMode",
	}

	expectedChefArgs := map[string]string{
		"notifyAddrs": "127.0.0.1:8080",
		"platform":    "openstack",
		"testMode":    "",
		"cleanupMode": "",
	}
	args := GetChefArgs(cmdArgs)
	for k, v := range expectedChefArgs {
		val, ok := args[k]
		require.True(t, ok, fmt.Sprintf("Key %s, Value %s exists", k, v))
		require.Equal(t, val, v, "Value matches")
	}
}

func TestChefDockerArgs(t *testing.T) {
	dockerArgs := []string{
		"--label", "cloudlet=cloudletname",
		"--label", "cloudletorg=cloudletorg",
		"--publish", ":9090",
		"--volume", "/tmp:/tmp",
		"--volume", "somefile:/etc/prometheus/prometheus.yml",
	}
	expectedChefArgs := map[string]interface{}{
		"label": []string{
			"cloudlet:cloudletname",
			"cloudletorg:cloudletorg",
		},
		"publish": ":9090",
		"volume": []string{
			"/tmp:/tmp",
			"somefile:/etc/prometheus/prometheus.yml",
		},
	}
	args := GetChefDockerArgs(dockerArgs)
	for k, eVal := range expectedChefArgs {
		val, ok := args[k]
		require.True(t, ok, fmt.Sprintf("Key %s, Value %s exists", k, eVal))
		argType, ok := ValidDockerArgs[k]
		require.True(t, ok, fmt.Sprintf("Valid docker arg %s", k))
		if argType == "list" {
			expectedVal, ok := eVal.([]string)
			cVal, ok := val.([]string)
			require.True(t, ok, fmt.Sprintf("Valid cast to []string for value %s", val))
			matchCount := 0
			for _, v1 := range cVal {
				for _, v2 := range expectedVal {
					if v1 == v2 {
						matchCount++
						break
					}
				}
			}
			require.Equal(t, matchCount, len(expectedVal), "Value matches")
		} else {
			cVal, ok := val.(string)
			require.True(t, ok, fmt.Sprintf("Valid cast to []string for value %s", val))
			require.Equal(t, cVal, val, "Value matches")
		}
	}
}

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

package k8smgmt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testCustomizationFileList = []string{"file1.yml", "file2.yml", "file3.yml"}
var testInvalidBooleanAnnotationStr = "version=val1.2,timeout"
var testValidBooleanAnnotationStr = "version=val1.2,wait=true,timeout=60"
var testInvalidAnnotationsVal = "version=1.2.2;touch /tmp/broken"
var testInvalidAnnotationsOpt = "version`touch /tmp/broken`;ls -lf /tmp/broken=1.2.2"

func TestHelm(t *testing.T) {
	str := getHelmYamlOpt(testCustomizationFileList)
	require.Equal(t, "-f file1.yml,file2.yml,file3.yml", str)
	str = getHelmYamlOpt([]string{})
	require.Equal(t, "", str)

	str, err := getHelmInstallOptsString("invalid annotations string")
	require.NotNil(t, err, "This should return an error")
	require.Equal(t, "", str, "error should return an empty string")
	str, err = getHelmInstallOptsString("")
	require.Nil(t, err, "No annotations should be a valid string")
	require.Equal(t, "", str, "empty options for empty annotations")
	str, err = getHelmInstallOptsString(testInvalidBooleanAnnotationStr)
	require.NotNil(t, err, "Incorrect way of specifying boolean option")
	require.Contains(t, err.Error(), "Invalid annotations string")
	require.Equal(t, "", str, "error should return an empty string")
	str, err = getHelmInstallOptsString(testInvalidAnnotationsVal)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\";\" not allowed in annotations")
	require.Equal(t, "", str, "error should return an empty string")
	str, err = getHelmInstallOptsString(testInvalidAnnotationsOpt)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"`\" not allowed in annotations")
	require.Equal(t, "", str, "error should return an empty string")

	str, err = getHelmInstallOptsString(testValidBooleanAnnotationStr)
	require.Nil(t, err)
	require.Equal(t, "--version \"val1.2\" --wait --timeout 60", str, "Invalid options string returned")

	imagePathTests := []struct {
		desc        string
		path        string
		expURL      string
		expRepoName string
		expChart    string
		expChartRef string
		expErr      string
	}{{
		"missing URL",
		"existing/testchart", "", "", "", "",
		"unsupported helm chart URL scheme",
	}, {
		"valid path",
		"http://testchartRepo.mex/charts:testcharts/testchart",
		"http://testchartRepo.mex/charts",
		"testcharts",
		"testchart",
		"testcharts/testchart",
		"",
	}, {
		"valid path with port",
		"https://testchartRepo.mex:8000/charts:testcharts/testchart",
		"https://testchartRepo.mex:8000/charts",
		"testcharts",
		"testchart",
		"testcharts/testchart",
		"",
	}, {
		"valid path with port 2",
		"https://helm.edgexr.org:edgexr/nexusai",
		"https://helm.edgexr.org",
		"edgexr",
		"nexusai",
		"edgexr/nexusai",
		"",
	}, {
		"missing repo name",
		"http://testchartRepo.mex/charts:testchart",
		"", "", "", "",
		"invalid repo/chart in helm image path",
	}, {
		"random string",
		"random string : ", "", "", "", "",
		"unsupported helm chart URL scheme for",
	}, {
		"oci path",
		"oci://testchartRepo.mex:8000/charts/testchart",
		"oci://testchartRepo.mex:8000/charts/testchart",
		"", "",
		"oci://testchartRepo.mex:8000/charts/testchart",
		"",
	}}
	for _, tt := range imagePathTests {
		spec, err := GetHelmChartSpec(tt.path)
		if tt.expErr != "" {
			require.NotNil(t, err, tt.desc)
			require.Contains(t, err.Error(), tt.expErr, tt.desc)
		} else {
			require.Nil(t, err, tt.desc)
			require.Equal(t, tt.expURL, spec.URLPath, tt.desc)
			require.Equal(t, tt.expRepoName, spec.RepoName, tt.desc)
			require.Equal(t, tt.expChart, spec.ChartName, tt.desc)
		}
	}
}

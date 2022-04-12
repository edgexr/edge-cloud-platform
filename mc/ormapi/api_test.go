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

package ormapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var reportFileNameTests = map[string][]string{
	"GDDT/GDDTReporter/20210420_20210503.pdf":                           []string{"GDDT", "GDDTReporter"},
	"GDDT_11111111_11111111/test/20210420_20210503.pdf":                []string{"GDDT_11111111_11111111", "test"},
	"GDDT_11111111_11111111_xyz_report.pdf/test/20210420_20210503.pdf": []string{"GDDT_11111111_11111111_xyz_report.pdf", "test"},
}

func TestReportFileName(t *testing.T) {
	for inp, out := range reportFileNameTests {
		orgName, reporterName := GetInfoFromReportFileName(inp)
		require.Equal(t, orgName, out[0])
		require.Equal(t, reporterName, out[1])
	}
}

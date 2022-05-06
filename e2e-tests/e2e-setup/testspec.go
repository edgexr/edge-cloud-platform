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

package e2esetup

import "github.com/edgexr/edge-cloud/setup-env/util"

type TestSpec struct {
	Name             string            `json:"name" yaml:"name"`
	ApiType          string            `json:"api" yaml:"api"`
	ApiFile          string            `json:"apifile" yaml:"apifile"`
	ApiFileVars      map[string]string `json:"apifilevars" yaml:"apifilevars"`
	Actions          []string          `json:"actions" yaml:"actions"`
	RetryCount       int               `json:"retrycount" yaml:"retrycount"`
	RetryIntervalSec float64           `json:"retryintervalsec" yaml:"retryintervalsec"`
	CurUserFile      string            `json:"curuserfile" yaml:"curuserfile"`
	CompareYaml      util.CompareYaml  `json:"compareyaml" yaml:"compareyaml"`
}

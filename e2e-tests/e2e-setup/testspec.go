package e2esetup

import "github.com/mobiledgex/edge-cloud/setup-env/util"

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

package e2esetup

type TestSpec struct {
	ApiType          string      `json:"api" yaml:"api"`
	ApiFile          string      `json:"apifile" yaml:"apifile"`
	Actions          []string    `json:"actions" yaml:"actions"`
	RetryCount       int         `json:"retrycount" yaml:"retrycount"`
	RetryIntervalSec float64     `json:"retryintervalsec" yaml:"retryintervalsec"`
	CurUserFile      string      `json:"curuserfile" yaml:"curuserfile"`
	CompareYaml      CompareYaml `json:"compareyaml" yaml:"compareyaml"`
}

type CompareYaml struct {
	Yaml1    string `json:"yaml1" yaml:"yaml1"`
	Yaml2    string `json:"yaml2" yaml:"yaml2"`
	FileType string `json:"filetype" yaml:"filetype"`
}

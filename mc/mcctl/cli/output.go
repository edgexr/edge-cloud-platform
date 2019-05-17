package cli

import (
	"encoding/json"
	"fmt"

	"github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
	yaml "github.com/mobiledgex/yaml/v2"
)

// note slightly different function in cmdsup.WriteOutputGeneric,
// perhaps we can consolidate them.
func WriteOutput(objs interface{}, format string) error {
	switch format {
	case cmdsup.OutputFormatYaml:
		output, err := yaml.Marshal(objs)
		if err != nil {
			return fmt.Errorf("yaml failed to marshal: %v\n", err)
		}
		fmt.Print(string(output))
	case cmdsup.OutputFormatJson:
		output, err := json.MarshalIndent(objs, "", "  ")
		if err != nil {
			return fmt.Errorf("json failed to marshal: %v\n", err)
		}
		fmt.Println(string(output))
	case cmdsup.OutputFormatJsonCompact:
		output, err := json.Marshal(objs)
		if err != nil {
			return fmt.Errorf("json failed to marshal: %v\n", err)
		}
		fmt.Println(string(output))
	default:
		return fmt.Errorf("invalid output format %s", format)
	}
	return nil
}

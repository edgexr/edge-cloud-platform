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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/template"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
)

// Generates mctestclient functions
func main() {
	printed := make(map[string]struct{})

	license := `// Copyright 2022 MobiledgeX, Inc
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

`

	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, license)
	fmt.Fprintf(buf, "package mctestclient\n")

	fmt.Fprintf(buf, "\nimport (\n")
	imports := []string{
		"github.com/edgexr/edge-cloud-infra/billing",
		"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl",
		"github.com/edgexr/edge-cloud-infra/mc/ormutil",
		"github.com/edgexr/edge-cloud-infra/mc/ormapi",
		"github.com/edgexr/edge-cloud/cli",
		"github.com/edgexr/edge-cloud/cloudcommon/node",
		"github.com/edgexr/edge-cloud/edgeproto",
		"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel",
	}
	for _, imp := range imports {
		fmt.Fprintf(buf, "\"%s\"\n", imp)
	}
	fmt.Fprintf(buf, ")\n")
	fmt.Fprintf(buf, "\n// Auto-generated code: DO NOT EDIT\n")

	names := []string{}
	for _, group := range ormctl.AllApis.Groups {
		names = append(names, group.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		group := ormctl.MustGetGroup(name)
		fmt.Fprintf(buf, "\n// Generating group %s\n", group.Name)
		err := printCommands(buf, group.Commands, printed)
		if err != nil {
			fmt.Printf("Failed: %v\n", err)
			os.Exit(1)
		}
	}
	names = []string{}
	for _, cmd := range ormctl.AllApis.Commands {
		if _, found := printed[cmd.Name]; found {
			continue
		}
		names = append(names, cmd.Name)
	}
	sort.Strings(names)
	fmt.Fprintf(buf, "\n// Generating ungrouped\n")
	for _, name := range names {
		cmd := ormctl.MustGetCommand(name)
		err := printCommand(buf, cmd)
		if err != nil {
			fmt.Printf("Failed: %v\n", err)
			os.Exit(1)
		}
	}
	byt, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Printf("%s\n", buf.String())
		fmt.Printf("Failed to format source: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(byt))
}

func printCommands(wr io.Writer, cmds []*ormctl.ApiCommand, printed map[string]struct{}) error {
	for _, cmd := range cmds {
		if _, found := printed[cmd.Name]; found {
			continue
		}
		err := printCommand(wr, cmd)
		if err != nil {
			return err
		}
		printed[cmd.Name] = struct{}{}
	}
	return nil
}

func printCommand(wr io.Writer, cmd *ormctl.ApiCommand) error {
	args := funcArgs{}
	args.Name = cmd.Name
	if strings.HasPrefix(cmd.Path, "/auth") {
		args.TokenArg = ", token string"
	}
	if cmd.ReqData != nil {
		inputMap := false
		if !cmd.ProtobufApi {
			if strings.HasPrefix(cmd.Name, "Update") || cmd.IsUpdate {
				// updates get passed in maps for REST-based APIs,
				// or should have fields set for Protobuf-based APIs.
				inputMap = true
			}
			if cmd.ShowFilter {
				// MC API show filter input data should be a
				// StructNamespace map
				inputMap = true
			}
		}
		if cmd.ProtobufApi && strings.HasPrefix(cmd.Name, "Update") {
			args.ProtobufUpdate = true
		}
		if inputMap {
			args.InArg = ", in *cli.MapData"
		} else {
			args.InArg = fmt.Sprintf(", in %T", cmd.ReqData)
		}
	}
	if cmd.ReplyData != nil {
		outType := reflect.TypeOf(cmd.ReplyData)
		if outType.Kind() == reflect.Ptr {
			outType = outType.Elem()
		}
		args.NilOut = "nil"
		if cmd.StreamOut {
			// Streaming API, ReplyData is a single object.
			// Run function should be able to read streamed
			// objects and combine them into an array.
			args.StreamOut = true
			args.OutArg = "[]" + outType.String() + ", "
			args.OutType = "[]" + outType.String()
		} else {
			// check if output is pointer to array,
			// because then we'll return the array value instead.
			if outType.Kind() == reflect.Slice || outType.Kind() == reflect.Map || outType.Kind() == reflect.String {
				args.OutArg = outType.String() + ", "
				if outType.Kind() == reflect.String {
					args.NilOut = `""`
				}
			} else {
				args.OutArg = "*" + outType.String() + ", "
				args.OutRef = "&"
			}
			args.OutType = outType.String()
		}
	}
	return funcT.Execute(wr, &args)
}

type funcArgs struct {
	Name           string
	TokenArg       string
	InArg          string
	OutArg         string
	OutType        string
	OutRef         string
	StreamOut      bool
	NilOut         string
	ProtobufUpdate bool
}

var funcT = template.Must(template.New("func").Parse(`
func (s *Client) {{.Name}}(uri string{{.TokenArg}}{{.InArg}}) ({{.OutArg}}int, error) {
	rundata := RunData{}
	rundata.Uri = uri
{{- if .TokenArg}}
	rundata.Token = token
{{- end}}
{{- if .InArg}}
{{- if .ProtobufUpdate}}
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
{{- if.OutType}}
		return {{.NilOut}}, 0, err
{{- else}}
		return 0, err
{{- end}}
	}
	rundata.In = mm
{{- else}}
	rundata.In = in
{{- end}}
{{- end}}
{{- if .OutType}}
	var out {{.OutType}}
	rundata.Out = &out
{{- end}}

	apiCmd := ormctl.MustGetCommand("{{.Name}}")
	s.ClientRun.Run(apiCmd, &rundata)
{{- if .OutType}}
	if rundata.RetError != nil {
		return {{.NilOut}}, rundata.RetStatus, rundata.RetError
	}
	return {{.OutRef}}out, rundata.RetStatus, rundata.RetError
{{- else}}
	return rundata.RetStatus, rundata.RetError
{{- end}}
}
`))

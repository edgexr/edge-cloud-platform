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
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	parsecomments "github.com/edgexr/edge-cloud-platform/pkg/parse-comments"
)

type arrayFlags []string

func (f *arrayFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *arrayFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var apiFiles arrayFlags
	var outFile string
	var pkgName string
	flag.StringVar(&pkgName, "pkgName", "", "package name (defaults to source dir)")
	flag.Var(&apiFiles, "apiFile", "package dir of api files to parse")
	flag.StringVar(&outFile, "outFile", "api.comments.go", "package dir of api files to parse")
	flag.Parse()

	if len(apiFiles) == 0 {
		log.Fatal("Must specify apiFiles")
	}

	if outFile == "" {
		log.Fatal("Must specify outFile")
	}

	pc := parsecomments.NewParseComments()
	err := pc.ParseFiles(apiFiles...)
	if err != nil {
		log.Fatalf("Failed to parse comments: %s", err)
	}

	if len(pc.Structs) == 0 {
		log.Fatalf("No structs found")
	}
	if pkgName == "" {
		pkgName = filepath.Base(pc.Structs[0].Pkg)
	}

	// write comments
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "package %s", pkgName)
	fmt.Fprintf(buf, "\n// This is an auto-generated file. DO NOT EDIT directly.\n")

	for _, st := range pc.Structs {
		fields := getFieldComments(pc, st, []string{})
		if len(fields) == 0 {
			continue
		}
		fmt.Fprintf(buf, "\nvar %sComments = map[string]string{\n", st.Name)
		for _, field := range fields {
			fmt.Fprintf(buf, "\"%s\": `%s`,\n", strings.ToLower(field.name), field.comment)
		}
		fmt.Fprintf(buf, "}\n")
	}

	// format the generated code
	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("Failed to format generated code: %v\n%s", err, buf.String())
	}
	// write output file
	err = ioutil.WriteFile(outFile, out, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file %s: %v", outFile, err)
	}
}

type Field struct {
	name    string
	comment string
}

func getFieldComments(pc *parsecomments.ParseComments, st *parsecomments.Struct, parents []string) []*Field {
	fields := []*Field{}
	for _, ref := range st.Embedded {
		emb, ok := pc.FindStruct(ref)
		if ok {
			fields = append(fields, getFieldComments(pc, emb, append(parents, emb.Name))...)
		}
	}
	for _, field := range st.Fields {
		ref := parsecomments.GetPkgStructName(field.TypePkg, field.TypeName)
		sub, ok := pc.FindStruct(ref)
		if ok {
			// sub struct
			name := field.Name
			if field.ArrayedInParent {
				name += ":#"
			}
			subFields := getFieldComments(pc, sub, append(parents, name))
			fields = append(fields, subFields...)
		} else if field.Comment != "" {
			f := &Field{
				name:    strings.Join(append(parents, field.Name), "."),
				comment: field.Comment,
			}
			if field.MapType == parsecomments.MapTypeStringString {
				f.comment += ", value is key=value format"
			}
			fields = append(fields, f)
		}
	}
	return fields
}

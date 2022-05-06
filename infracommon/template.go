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

package infracommon

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/edgexr/edge-cloud/log"
)

func ExecTemplate(templateName, templateString string, templateData interface{}) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	funcMap := template.FuncMap{
		"Indent": func(values ...interface{}) string {
			s := values[0].(string)
			l := 4
			if len(values) > 1 {
				l = values[1].(int)
			}
			var newStr []string
			indent := strings.Repeat(" ", l)
			for _, v := range strings.Split(string(s), "\n") {
				newStr = append(newStr, indent+v)
			}
			return strings.Join(newStr, "\n")
		},
	}

	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(templateString)
	if err != nil {
		// this is a bug
		log.WarnLog("template new failed", "templateString", templateString, "err", err)
		return nil, fmt.Errorf("template new failed: %s", err)
	}
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		return nil, fmt.Errorf("Template Execute Failed: %s", err)
	}
	return &buf, nil
}

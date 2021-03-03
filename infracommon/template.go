package infracommon

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/mobiledgex/edge-cloud/log"
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

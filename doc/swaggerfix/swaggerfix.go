package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func main() {
	fileName := os.Args[1]
	doc, err := loads.Spec(fileName)
	if err != nil {
		log.Fatal(err)
	}
	v := NewValidator()
	v.Validate(doc)
	out, err := json.MarshalIndent(v.sw, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	ioutil.WriteFile(fileName, out, 0666)
	if v.HasFailures() {
		v.PrintFailures()
		os.Exit(1)
	}
}

type Validator struct {
	descMissing map[string]struct{}
	apiCommands map[string]*ormctl.ApiCommand // key is path
	sw          *spec.Swagger
}

func NewValidator() *Validator {
	v := Validator{}
	v.descMissing = make(map[string]struct{})
	v.apiCommands = make(map[string]*ormctl.ApiCommand)
	for _, api := range ormctl.AllApis.Commands {
		v.apiCommands[api.Path] = api
	}
	return &v
}

func (s *Validator) Validate(doc *loads.Document) {
	sw := doc.Spec()
	s.validatePaths(sw)
	s.sw = sw
}

func (s *Validator) validatePaths(sw *spec.Swagger) {
	if sw.Paths == nil {
		return
	}
	newPaths := make(map[string]spec.PathItem)
	for apiPath, pathItem := range sw.Paths.Paths {
		api, ok := s.apiCommands[apiPath]
		if !ok {
			log.Fatal("ApiCommand not found for path " + apiPath)
		}
		fieldPrefix := ""
		if api.ProtobufApi {
			// required/optional/noconfig field names are
			// relative to protobuf object, not regionproto object.
			regionObj, ok := api.ReqData.(ormapi.RegionObjWithFields)
			if ok {
				fieldPrefix = regionObj.GetObjName() + "."
			}
		}
		noconfig := make(map[string]struct{})
		for _, field := range strings.Split(api.NoConfig, ",") {
			noconfig[fieldPrefix+field] = struct{}{}
		}
		aliases := make(map[string]string)
		for _, alias := range strings.Fields(api.AliasArgs) {
			ar := strings.SplitN(alias, "=", 2)
			if len(ar) != 2 {
				continue
			}
			aliases[ar[0]] = ar[1]
		}
		configLC := make(map[string]struct{})
		for _, arg := range append(strings.Fields(api.RequiredArgs), strings.Fields(api.OptionalArgs)...) {
			if a, ok := aliases[arg]; ok {
				arg = a
			}
			configLC[arg] = struct{}{}
		}

		s.validateOperation(api, noconfig, configLC, "GET", pathItem.Get)
		s.validateOperation(api, noconfig, configLC, "PUT", pathItem.Put)
		s.validateOperation(api, noconfig, configLC, "POST", pathItem.Post)
		s.validateOperation(api, noconfig, configLC, "DELETE", pathItem.Delete)
		s.validateOperation(api, noconfig, configLC, "OPTIONS", pathItem.Options)
		s.validateOperation(api, noconfig, configLC, "HEAD", pathItem.Head)
		s.validateOperation(api, noconfig, configLC, "PATCH", pathItem.Patch)
		newPaths[apiPath] = pathItem
	}
	// put back paths if modified
	sw.Paths.Paths = newPaths
}

func (s *Validator) validateOperation(api *ormctl.ApiCommand, noconfig, configLC map[string]struct{}, opName string, op *spec.Operation) {
	if op == nil {
		return
	}
	if op.Description == "" && op.Summary == "" {
		s.addOperationDescMissing(api.Path, opName)
	}
	if op.Summary != "" {
		// remove trailing period from summary
		op.Summary = strings.TrimSpace(op.Summary)
		op.Summary = strings.TrimSuffix(op.Summary, ".")
	}
	for _, param := range op.Parameters {
		if param.Schema == nil {
			continue
		}
		s.validateSchema(api, noconfig, configLC, []string{}, param.Schema)
	}
}

func (s *Validator) validateSchema(api *ormctl.ApiCommand, noconfig, configLC map[string]struct{}, parents []string, schema *spec.Schema) {
	for propName, propSchema := range schema.Properties {
		name, found := propSchema.Extensions.GetString("x-go-name")
		if !found {
			name = propName
		}
		// remove noconfig fields from API spec
		hierName := strings.Join(append(parents, name), ".")
		if _, found := noconfig[hierName]; found {
			delete(schema.Properties, propName)
			continue
		}
		if len(propSchema.Properties) == 0 {
			// remove field if not required or optional arg
			if _, found := configLC[strings.ToLower(hierName)]; !found {
				delete(schema.Properties, propName)
				continue
			}
		}
		// make sure field has description for documentation
		if propSchema.Description == "" {
			s.addSchemaDescMissing(api, parents, name)
		}
		s.validateSchema(api, noconfig, configLC, append(parents, name), &propSchema)
		// in case propSchema was modified, add it back
		schema.Properties[propName] = propSchema
	}
}

func (s *Validator) addOperationDescMissing(apiPath, opName string) {
	str := fmt.Sprintf("Path %s op %s", apiPath, opName)
	s.descMissing[str] = struct{}{}
}

func (s *Validator) addSchemaDescMissing(api *ormctl.ApiCommand, parents []string, name string) {
	path := append(parents, name)
	str := fmt.Sprintf("Field %T.%s", api.ReqData, strings.Join(path, "."))
	s.descMissing[str] = struct{}{}
}

func (s *Validator) HasFailures() bool {
	return len(s.descMissing) > 0
}

func (s *Validator) PrintFailures() {
	if len(s.descMissing) > 0 {
		descMissing := []string{}
		for missing, _ := range s.descMissing {
			descMissing = append(descMissing, missing)
		}
		sort.Strings(descMissing)
		fmt.Printf("The following objects are missing a description or summary, which requires a comment on the field or api:\n")
		for _, missing := range descMissing {
			fmt.Println("  " + missing)
		}
	}
}

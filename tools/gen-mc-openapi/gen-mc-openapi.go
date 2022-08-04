// This program generates an openapi 3.0 doc based on the
// APIs defined in pkg/mcctl/ormctl.
// Those files are both hand-written and auto-generated descriptions
// of all our the MC APIs.
// This program adds that information into a hand-written base doc,
// to allow us to add custom data into the doc.
// Additionally, the program uses file parsing to pull comments from
// the struct fields to use as the field descriptions.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/ormctl"
	parsecomments "github.com/edgexr/edge-cloud-platform/pkg/parse-comments"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go/openapi3"
	"gopkg.in/yaml.v2"
)

type arrayFlags []string

func (f *arrayFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *arrayFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var debug = flag.Bool("debug", false, "write out debug info")

func main() {
	var scanPaths arrayFlags
	var baseFile = flag.String("baseFile", "base.yaml", "base openapiv3 yaml file")
	var outFile = flag.String("outFile", "openapi.yaml", "output openapiv3 yaml file name")
	var groupsDir = flag.String("groupsDir", "./groups", "directory path for apis separated by group")
	flag.Var(&scanPaths, "scanPath", "go package directory of api files, or go file to scan for comments, may be specified multiple times")
	flag.Parse()

	g := NewGenerator()
	g.genDoc(scanPaths, *baseFile, *outFile, *groupsDir)
	if g.failed {
		fmt.Fprintf(os.Stderr, "Error: some fields lacked descriptions")
		os.Exit(1)
	}
}

const basePath = "/api/v1"
const mimeJson = "application/json"

func NewGenerator() *Generator {
	g := Generator{}
	return &g
}

type Generator struct {
	parseComments *parsecomments.ParseComments
	failed        bool
}

func (s *Generator) genDoc(scanPaths arrayFlags, baseFileName, outFileName, groupsDirName string) {
	// first parse any comments
	s.parseComments = parsecomments.NewParseComments()
	if err := s.parseComments.ParseFiles(scanPaths...); err != nil {
		log.Fatalf("failed to parse api files: %s", err)
	}

	if *debug {
		out, err := yaml.Marshal(s.parseComments)
		if err == nil {
			fmt.Printf("%s\n", string(out))
		}
	}

	// open base file
	baseDat, err := ioutil.ReadFile(baseFileName)
	if err != nil {
		log.Fatalf("failed to read base file %s: %s", baseFileName, err)
	}
	all := newReflector(baseDat)

	err = os.MkdirAll(groupsDirName, 0777)
	if err != nil {
		log.Fatalf("failed to make groups dir %s: %s", groupsDirName, err)
	}

	grouped := map[string]struct{}{}
	for gname, group := range ormctl.AllApis.Groups {
		if err := s.processGroup(all, baseDat, groupsDirName, group, grouped); err != nil {
			log.Fatalf("failed to process group %s: %s", gname, err)
		}
	}
	ungrouped := &ormctl.ApiGroup{
		Name: "Ungrouped",
		Desc: "Ungrouped APIs",
	}
	for _, cmd := range ormctl.AllApis.Commands {
		if _, found := grouped[cmd.Name]; found {
			continue
		}
		if cmd.DuplicateForCli {
			continue
		}
		ungrouped.Commands = append(ungrouped.Commands, cmd)
	}
	if err := s.processGroup(all, baseDat, groupsDirName, ungrouped, grouped); err != nil {
		log.Fatalf("failed to process ungrouped: %s", err)
	}

	err = writeSpec(all.Spec, outFileName)
	if err != nil {
		log.Fatalf("failed to write data to file %s: %s", outFileName, err)
	}
}

func newReflector(baseDat []byte) *openapi3.Reflector {
	r := &openapi3.Reflector{
		Spec: &openapi3.Spec{},
	}
	err := r.Spec.UnmarshalYAML(baseDat)
	if err != nil {
		log.Fatalf("failed to unmarshal base yaml file: %s", err)
	}
	r.Spec.Paths.MapOfPathItemValues = make(map[string]openapi3.PathItem)
	return r
}

func writeSpec(spec *openapi3.Spec, outFileName string) error {
	dat, err := spec.MarshalYAML()
	if err != nil {
		return fmt.Errorf("failed to marshal yaml for spec: %s", err)
	}
	buf := bytes.Buffer{}
	buf.Write([]byte("# Auto-generated doc: DO NOT EDIT\n"))
	buf.Write(dat)
	err = ioutil.WriteFile(outFileName, buf.Bytes(), 0666)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %s", outFileName, err)
	}
	return nil
}

func (s *Generator) processGroup(all *openapi3.Reflector, baseDat []byte, groupsDirName string, group *ormctl.ApiGroup, grouped map[string]struct{}) error {
	gRef := newReflector(baseDat)
	gRef.Spec.Info.Title = group.Name + " APIs"
	desc := "Master Controller APIs for " + group.Name + "s"
	gRef.Spec.Info.Description = &desc
	// tags and x-tagGroups from baseDat are only used for grouping in the
	// top level openapi doc.
	gRef.Spec.Tags = nil
	gRef.Spec.MapOfAnything = nil

	// Because the single unified file gets too large to read, we generate
	// both a single unified file for redocly, and separate group-based
	// files for easy human readability.
	gFile := groupsDirName + "/" + group.Name + ".yaml"
	for _, cmd := range group.Commands {
		if cmd.DuplicateForCli {
			continue
		}
		err := s.processCmd(all, cmd)
		if err != nil {
			return err
		}
		err = s.processCmd(gRef, cmd)
		if err != nil {
			return err
		}
		grouped[cmd.Name] = struct{}{}
	}
	if err := writeSpec(gRef.Spec, gFile); err != nil {
		return fmt.Errorf("failed to write file %s for group %s: %s", gFile, group.Name, err)
	}
	return nil
}

func (s *Generator) processCmd(reflector *openapi3.Reflector, cmd *ormctl.ApiCommand) error {
	op := openapi3.Operation{
		Summary:     &cmd.Name,
		Description: &cmd.Short,
		ID:          &cmd.Name,
	}
	if cmd.Group != "" {
		op.Tags = []string{cmd.Group}
	}
	requiresAuth := strings.HasPrefix(cmd.Path, "/auth/")
	if requiresAuth {
		auth := map[string][]string{}
		auth["bearerAuth"] = []string{}
		op.Security = append(op.Security, auth)
		s.addBearerScheme(reflector)
	}

	if cmd.ReqData != nil {
		s.setRequest(&op, cmd.ReqData, cmd)
		if err := s.addComponent(reflector, cmd.ReqData, cmd); err != nil {
			return err
		}
	}
	replyData := cmd.ReplyData
	if replyData == nil {
		if cmd.ProtobufApi {
			replyData = new(edgeproto.Result)
		} else {
			replyData = new(ormapi.Result)
		}
	}
	s.addResponse(&op, http.StatusOK, replyData, cmd.ReplyMimeType, cmd.ReplyDescription)
	if err := s.addComponent(reflector, replyData, cmd); err != nil {
		return err
	}
	if cmd.FailureResponses == nil {
		if err := s.addComponent(reflector, new(ormapi.Result), cmd); err != nil {
			return err
		}
		s.addResponse(&op, http.StatusBadRequest, new(ormapi.Result), "", "")
		if requiresAuth {
			s.addResponse(&op, http.StatusForbidden, nil, "", "")
		}
	}
	for _, failResp := range cmd.FailureResponses {
		s.addResponse(&op, failResp.Code, failResp.Data, "", "")
		if err := s.addComponent(reflector, failResp.Data, cmd); err != nil {
			return err
		}
	}
	reflector.Spec.AddOperation(http.MethodPost, basePath+cmd.Path, op)
	return nil
}

func (s *Generator) setRequest(op *openapi3.Operation, data interface{}, cmd *ormctl.ApiCommand) {
	req := openapi3.RequestBody{}
	req.Content = make(map[string]openapi3.MediaType)
	med := openapi3.MediaType{
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: getObjRef(data),
			},
		},
	}
	aliases := make(map[string]string)
	for _, kv := range strings.Split(cmd.AliasArgs, " ") {
		kvs := strings.Split(kv, "=")
		if len(kvs) != 2 {
			continue
		}
		aliases[kvs[0]] = kvs[1]
	}
	requiredArgs := []string{}
	for _, arg := range strings.Split(cmd.RequiredArgs, " ") {
		if arg == "" {
			continue
		}
		if hierName, ok := aliases[arg]; ok {
			arg = hierName
		}
		requiredArgs = append(requiredArgs, arg)
	}

	if len(requiredArgs) > 0 {
		med.MapOfAnything = map[string]interface{}{
			"x-required-fields": requiredArgs,
		}
	}
	req.Content[mimeJson] = med
	op.RequestBody = &openapi3.RequestBodyOrRef{}
	op.RequestBody.RequestBody = &req
}

func (s *Generator) addResponse(op *openapi3.Operation, code int, data interface{}, mimeType, desc string) {
	resp := openapi3.Response{}
	if desc == "" {
		resp.Description = http.StatusText(code)
	} else {
		resp.Description = desc
	}
	if mimeType == "" {
		mimeType = mimeJson
	}
	if data != nil {
		typ, arrayed := getBaseType(data)

		sref := &openapi3.SchemaOrRef{}
		switch typ {
		case bytesType:
			schemaType := openapi3.SchemaTypeString
			format := "binary"
			sref.Schema = &openapi3.Schema{
				Type:   &schemaType,
				Format: &format,
			}
		case genericMapType:
			schemaType := openapi3.SchemaTypeString
			sref.Schema = &openapi3.Schema{
				Type: &schemaType,
			}
		case reflect.TypeOf(string("")):
			schemaType := openapi3.SchemaTypeString
			sref.Schema = &openapi3.Schema{
				Type: &schemaType,
			}
		default:
			sref.SchemaReference = &openapi3.SchemaReference{
				Ref: getTypeRef(typ),
			}
		}
		if arrayed {
			// wrap ref in arrayed schema
			schemaType := openapi3.SchemaTypeArray
			sref = &openapi3.SchemaOrRef{
				Schema: &openapi3.Schema{
					Type:  &schemaType,
					Items: sref,
				},
			}
		}
		resp.Content = make(map[string]openapi3.MediaType)
		resp.Content[mimeType] = openapi3.MediaType{
			Schema: sref,
		}
	}
	op.Responses.WithMapOfResponseOrRefValuesItem(strconv.Itoa(code), openapi3.ResponseOrRef{
		Response: &resp,
	})
}

func (s *Generator) addComponent(reflector *openapi3.Reflector, obj interface{}, cmd *ormctl.ApiCommand) error {
	baseType, _ := getBaseType(obj)
	typeString := getTypeName(baseType)
	if s.hasDefinition(reflector, typeString) {
		return nil
	}

	noconfig := make(map[string]struct{})
	for _, hierName := range strings.Split(cmd.NoConfig, ",") {
		noconfig[strings.ToLower(hierName)] = struct{}{}
	}

	var rc *jsonschema.ReflectContext
	contextDefs := make(map[string]struct{})
	callStack := []reflect.Type{}
	_, err := reflector.Reflect(obj,
		jsonschema.DefinitionsPrefix(componentPrefix),
		jsonschema.RootRef,
		jsonschema.ProcessWithoutTags,
		func(captureRc *jsonschema.ReflectContext) {
			rc = captureRc
		},
		jsonschema.CollectDefinitions(func(name string, schema jsonschema.Schema) {
			if ok, _ := isBuiltinJSONType(schema.ReflectType); ok {
				return
			}
			s.collectDefinition(reflector, name, schema)
		}),
		jsonschema.InterceptType(func(v reflect.Value, schema *jsonschema.Schema) (bool, error) {
			// InterceptType gets called both before and after
			// walking object. But, the signature doesn't indicate which
			// one, and it's not perfectly symmetric, since if the
			// definition has already been parsed and the reflect walk
			// avoids reparsing it, it gets called on entry but not exit.
			// Because calls are unbalanced and we shouldn't have any loops,
			// we detect the exit case by seeing if the typeString has
			// already been handled.
			pad := ""
			for range callStack {
				pad += "  "
			}
			callType := v.Type()
			if len(callStack) == 0 || callStack[len(callStack)-1] != callType {
				typeString := getTypeName(v.Type())
				if _, found := contextDefs[typeString]; found {
					return false, nil
				}
				contextDefs[typeString] = struct{}{}

				// called on enter, push onto stack
				pad := ""
				for range callStack {
					pad += "  "
				}
				callStack = append(callStack, callType)
				if *debug {
					fmt.Printf("%s%s: push %s\n", pad, cmd.Name, v.Type().String())
				}
			} else if callStack[len(callStack)-1] == callType {
				// called on exit, pop from stack
				callStack = callStack[:len(callStack)-1]
				pad := ""
				for range callStack {
					pad += "  "
				}
				if *debug {
					fmt.Printf("%s%s: pop %s\n", pad, cmd.Name, v.Type().String())
				}
			}
			return false, nil
		}),
		jsonschema.InterceptProperty(func(name string, field reflect.StructField, propertySchema *jsonschema.Schema) error {
			// Note: InterceptProperty gets called for each field, but
			// the field's type definition is processed before this
			// intercept is called. This leads to some strange behavior
			// where we return "ErrSkipProperty" here, and the property is
			// indeed not added to the final parent definition, but its definition
			// still ends up getting parsed and recursed into. Just FYI.
			if cmd.ProtobufApi && strings.ToLower(name) == "fields" && field.Type == stringArrayType {
				return jsonschema.ErrSkipProperty
			}
			// We need to figure out the hierarchical name to see if
			// it's been marked noconfig in the proto annotations.
			// First element in rc.Path is #, so ignore it.
			start := 1
			path := []string{}
			for ii := start; ii < len(rc.Path); ii++ {
				if rc.Path[ii] == "[]" {
					continue
				}
				path = append(path, rc.Path[ii])
			}
			path = append(path, name)
			hierName := strings.ToLower(strings.Join(path, "."))
			hierName = strings.ReplaceAll(hierName, "_", "")

			// no config names are never aliased
			if _, found := noconfig[hierName]; found {
				return jsonschema.ErrSkipProperty
			}

			// look up comments
			parentType := baseType
			if len(callStack) >= 1 {
				parentType = callStack[len(callStack)-1]
			}
			if parentType == nil {
				if *debug {
					fmt.Printf("ParentType is nil for %s: %s\n", cmd.Name, hierName)
				}
				return nil
			}
			if parentType.Kind() == reflect.Ptr {
				parentType = parentType.Elem()
			}

			desc := ""
			if field, ok := s.parseComments.FindField(parentType.PkgPath(), parentType.Name(), field.Name); ok {
				if field.Hidden {
					return jsonschema.ErrSkipProperty
				}
				if field.ReadOnly {
					propertySchema.ReadOnly = &field.ReadOnly
				}
				desc = field.Comment
			}
			if desc != "" {
				propertySchema.Description = &desc
			} else if !cmd.DocEmptyCommentsOk {
				fmt.Printf("Description not found for cmd %s.%s (%s): %s.%s.%s\n", cmd.Group, cmd.Name, hierName, parentType.PkgPath(), parentType.Name(), field.Name)
				s.failed = true
			}

			if ok, extraHelp := isBuiltinJSONType(field.Type); ok {
				typ := &jsonschema.Type{}
				typ = typ.WithSimpleTypes(jsonschema.String)
				propertySchema.Type = typ
				propertySchema.Ref = nil
				if extraHelp != "" {
					desc = desc + extraHelp
				}
			}
			return nil
		}))
	if err != nil {
		return err
	}
	return err
}

func (s *Generator) addBearerScheme(r *openapi3.Reflector) {
	format := "JWT"
	desc := "JWT token generated by the login API to be included in the http header"
	sec := &openapi3.HTTPSecurityScheme{
		Scheme:       "bearer",
		BearerFormat: &format,
		Description:  &desc,
	}
	sref := openapi3.SecuritySchemeOrRef{
		SecurityScheme: &openapi3.SecurityScheme{
			HTTPSecurityScheme: sec,
		},
	}
	r.SpecEns().ComponentsEns().SecuritySchemesEns().WithMapOfSecuritySchemeOrRefValuesItem("bearerAuth", sref)
}

func (s *Generator) collectDefinition(r *openapi3.Reflector, name string, schema jsonschema.Schema) {
	if _, exists := r.SpecEns().ComponentsEns().SchemasEns().MapOfSchemaOrRefValues[name]; exists {
		return
	}
	sref := openapi3.SchemaOrRef{}
	sref.FromJSONSchema(schema.ToSchemaOrBool())
	r.SpecEns().ComponentsEns().SchemasEns().WithMapOfSchemaOrRefValuesItem(name, sref)
}

func (s *Generator) hasDefinition(r *openapi3.Reflector, name string) bool {
	if r.Spec == nil || r.Spec.Components == nil || r.Spec.Components.Schemas == nil || r.Spec.Components.Schemas.MapOfSchemaOrRefValues == nil {
		return false
	}
	_, found := r.Spec.Components.Schemas.MapOfSchemaOrRefValues[name]
	return found
}

// Builtin types should not have their own component defined, as they can
// be unmarshaled from a string. Returns an optional extra help info.
func isBuiltinJSONType(typ reflect.Type) (bool, string) {
	// For enums, don't create a separate definition for them,
	// just treat them as strings inline, since enums in edgeproto
	// can unmarshal either ints or strings.
	_, extraHelp, isProtoEnum := edgeproto.GetEnumParseHelp(typ)
	if isProtoEnum {
		return true, extraHelp
	}
	if typ == reflect.TypeOf(edgeproto.Duration(0)) ||
		typ == reflect.TypeOf(time.Duration(0)) ||
		typ == reflect.TypeOf(time.Time{}) ||
		typ == reflect.TypeOf(dmeproto.Timestamp{}) ||
		typ == reflect.TypeOf(edgeproto.Udec64{}) {
		return true, ""
	}
	return false, ""
}

const componentPrefix = "#/components/schemas/"

var bytesNil = []byte(nil)
var bytesType = reflect.TypeOf(bytesNil)
var genericMap = map[string]interface{}{}
var genericMapType = reflect.TypeOf(genericMap)
var stringArray = []string{}
var stringArrayType = reflect.TypeOf(stringArray)

func getBaseType(obj interface{}) (reflect.Type, bool) {
	typ := reflect.TypeOf(obj)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	// handle special builtin types
	if typ == bytesType {
		return bytesType, false
	} else if typ == genericMapType {
		return genericMapType, false
	}

	arrayed := false
	if typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		arrayed = true
		typ = typ.Elem()
	}
	return typ, arrayed
}

func getObjRef(obj interface{}) string {
	return componentPrefix + getObjName(obj)
}

func getTypeRef(typ reflect.Type) string {
	return componentPrefix + getTypeName(typ)
}

func getObjName(obj interface{}) string {
	return getTypeName(reflect.TypeOf(obj))
}

func getTypeName(typ reflect.Type) string {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	// This needs to match the behavior of jsonschema.defName()
	return util.CamelCase(path.Base(typ.PkgPath())) + strings.Title(typ.Name())
}

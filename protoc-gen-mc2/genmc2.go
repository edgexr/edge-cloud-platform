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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
	"github.com/gogo/protobuf/protoc-gen-gogo/generator"
	"github.com/edgexr/edge-cloud/gensupport"
	"github.com/edgexr/edge-cloud/protogen"
)

type GenMC2 struct {
	*generator.Generator
	support            gensupport.PluginSupport
	tmpl               *template.Template
	tmplCtrlClient     *template.Template
	tmplApi            *template.Template
	tmplMethodTest     *template.Template
	tmplMethodTestutil *template.Template
	tmplMethodCtl      *template.Template
	tmplMessageTest    *template.Template
	regionStructs      map[string]struct{}
	inputMessages      map[string]*gensupport.MessageInfo
	firstFile          bool
	genctrlclient      bool
	genapi             bool
	gentest            bool
	gentestutil        bool
	genctl             bool
	importEcho         bool
	importHttp         bool
	importContext      bool
	importIO           bool
	importOS           bool
	importJson         bool
	importTesting      bool
	importRequire      bool
	importMctestclient bool
	importOrmapi       bool
	importOrmtestutil  bool
	importGrpcStatus   bool
	importStrings      bool
	importLog          bool
	importCli          bool
	importOrmutil      bool
	importCtrlClient   bool
}

func (g *GenMC2) Name() string {
	return "GenMC2"
}

func (g *GenMC2) Init(gen *generator.Generator) {
	g.Generator = gen
	g.tmpl = template.Must(template.New("mc2").Parse(tmpl))
	g.tmplCtrlClient = template.Must(template.New("mc2ctrlclient").Parse(tmplCtrlClient))
	g.tmplApi = template.Must(template.New("mc2api").Parse(tmplApi))
	g.tmplMethodTest = template.Must(template.New("methodtest").Parse(tmplMethodTest))
	g.tmplMethodTestutil = template.Must(template.New("methodtest").Parse(tmplMethodTestutil))
	g.tmplMethodCtl = template.Must(template.New("methodctl").Parse(tmplMethodCtl))
	g.tmplMessageTest = template.Must(template.New("messagetest").Parse(tmplMessageTest))
	g.regionStructs = make(map[string]struct{})
	g.firstFile = true
}

func (g *GenMC2) GenerateImports(file *generator.FileDescriptor) {
	g.support.PrintUsedImports(g.Generator)
	if g.importEcho {
		g.PrintImport("", "github.com/labstack/echo")
	}
	if g.importHttp {
		g.PrintImport("", "net/http")
	}
	if g.importContext {
		g.PrintImport("", "context")
	}
	if g.importIO {
		g.PrintImport("", "io")
	}
	if g.importOS {
		g.PrintImport("", "os")
	}
	if g.importJson {
		g.PrintImport("", "encoding/json")
	}
	if g.importTesting {
		g.PrintImport("", "testing")
	}
	if g.importStrings {
		g.PrintImport("", "strings")
	}
	if g.importRequire {
		g.PrintImport("", "github.com/stretchr/testify/require")
	}
	if g.importLog {
		g.PrintImport("", "github.com/edgexr/edge-cloud/log")
	}
	if g.importMctestclient {
		g.PrintImport("", "github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient")
	}
	if g.importOrmapi {
		g.PrintImport("", "github.com/edgexr/edge-cloud-infra/mc/ormapi")
	}
	if g.importOrmtestutil {
		g.PrintImport("", "github.com/edgexr/edge-cloud-infra/mc/orm/testutil")
	}
	if g.importCli {
		g.PrintImport("", "github.com/edgexr/edge-cloud/cli")
	}
	if g.importGrpcStatus {
		g.PrintImport("", "google.golang.org/grpc/status")
	}
	if g.importOrmutil {
		g.PrintImport("", "github.com/edgexr/edge-cloud-infra/mc/ormutil")
	}
	if g.importCtrlClient {
		g.PrintImport("", "github.com/edgexr/edge-cloud-infra/mc/ctrlclient")
	}
}

type ServiceProps struct {
	cliusebase string
	cliuses    map[string]string
	path       []string
}

func (s *ServiceProps) Init(serviceNum int) {
	s.cliuses = make(map[string]string)
	// path: 6 is service type
	s.path = []string{"6", strconv.Itoa(serviceNum)}
}

func (g *GenMC2) Generate(file *generator.FileDescriptor) {
	g.importEcho = false
	g.importHttp = false
	g.importContext = false
	g.importIO = false
	g.importOS = false
	g.importJson = false
	g.importTesting = false
	g.importStrings = false
	g.importRequire = false
	g.importMctestclient = false
	g.importOrmapi = false
	g.importOrmtestutil = false
	g.importGrpcStatus = false
	g.importLog = false
	g.importCli = false
	g.importOrmutil = false
	g.importCtrlClient = false

	g.support.InitFile()
	if !g.support.GenFile(*file.FileDescriptorProto.Name) {
		return
	}
	g.genctrlclient = g.hasParam("genctrlclient")
	g.genapi = g.hasParam("genapi")
	g.gentest = g.hasParam("gentest")
	g.gentestutil = g.hasParam("gentestutil")
	g.genctl = g.hasParam("genctl")
	g.inputMessages = gensupport.GetInputMessages(g.Generator, &g.support)
	if !g.genFile(file) {
		return
	}

	g.P(gensupport.AutoGenComment)

	methodGroups := gensupport.GetAllMethodGroups(g.Generator, &g.support)

	for ii, service := range file.FileDescriptorProto.Service {
		serviceProps := ServiceProps{}
		serviceProps.Init(ii)
		g.generateService(file, service, &serviceProps)
		if g.genctl {
			g.generateCtlGroup(service, methodGroups)
		}
		if len(service.Method) == 0 {
			continue
		}
		if g.gentestutil {
			g.generateRunApi(file.FileDescriptorProto, service)
		}
		if g.gentest {
			g.generateTestApi(service)
		}
	}
	if g.genctl {
		for ii, msg := range file.Messages() {
			_, found := g.inputMessages[*msg.DescriptorProto.Name]
			if !found {
				continue
			}
			methodGroup := methodGroups[*msg.DescriptorProto.Name]
			gensupport.GenerateMessageArgs(g.Generator, &g.support, msg, methodGroup, true, ii)
		}
	}

	if g.genctrlclient || g.genapi || g.genctl || g.gentestutil {
		return
	}

	if g.firstFile {
		if !g.gentest {
			g.generatePosts()
		}
		g.firstFile = false
	}
}

func (g *GenMC2) genFile(file *generator.FileDescriptor) bool {
	if len(file.FileDescriptorProto.Service) != 0 {
		for _, service := range file.FileDescriptorProto.Service {
			if len(service.Method) == 0 {
				continue
			}
			for _, method := range service.Method {
				if gensupport.ClientStreaming(method) {
					continue
				}
				if g.gentestutil {
					return true
				}
				if GetMc2Api(method) != "" {
					return true
				}
			}
		}
	}
	if g.genctl {
		for _, msg := range file.Messages() {
			_, found := g.inputMessages[*msg.DescriptorProto.Name]
			if found {
				return true
			}
		}
	}
	return false
}

func (g *GenMC2) generatePosts() {
	g.P("func addControllerApis(method string, group *echo.Group) {")

	for _, file := range g.Generator.Request.ProtoFile {
		if !g.support.GenFile(*file.Name) {
			continue
		}
		if len(file.Service) == 0 {
			continue
		}
		for serviceIndex, service := range file.Service {
			if len(service.Method) == 0 {
				continue
			}
			for methodIndex, method := range service.Method {
				if GetMc2Api(method) == "" {
					continue
				}

				// 6 means service
				// 2 means method in a service
				summary := g.support.GetComments(file.GetName(), fmt.Sprintf("6,%d,2,%d", serviceIndex, methodIndex))
				summary = strings.TrimSpace(strings.Map(gensupport.RemoveNewLines, summary))
				g.genSwaggerSpec(method, summary)

				g.P("group.Match([]string{method}, \"/ctrl/", method.Name,
					"\", ", method.Name, ")")
			}
		}
	}
	g.P("}")
	g.P()
}

func (g *GenMC2) getFields(names, nums []string, desc *generator.Descriptor) []string {
	allStr := []string{}
	message := desc.DescriptorProto
	for ii, field := range message.Field {
		if ii == 0 && *field.Name == "fields" {
			continue
		}
		name := generator.CamelCase(*field.Name)
		num := fmt.Sprintf("%d", *field.Number)
		allStr = append(allStr, fmt.Sprintf("%s: %s", strings.Join(append(names, name), ""), strings.Join(append(nums, num), ".")))
		if *field.Type == descriptor.FieldDescriptorProto_TYPE_MESSAGE {
			subDesc := gensupport.GetDesc(g.Generator, field.GetTypeName())
			allStr = append(allStr, g.getFields(append(names, name), append(nums, num), subDesc)...)
		}
	}
	return allStr
}

func (g *GenMC2) genSwaggerSpec(method *descriptor.MethodDescriptorProto, summary string) {
	in := gensupport.GetDesc(g.Generator, method.GetInputType())
	inname := *in.DescriptorProto.Name
	g.P("// swagger:route POST /auth/ctrl/", method.Name, " ", inname, " ", method.Name)
	out := strings.Split(summary, ".")
	if len(out) > 1 {
		g.P("// ", out[0], ".")
		g.P("// ", strings.Join(out[1:len(out)], "."))
	} else {
		g.P("// ", out[0], ".")
	}
	if strings.HasPrefix(*method.Name, "Update") {
		allStr := g.getFields([]string{}, []string{}, in)
		g.P("// The following values should be added to `", inname, ".fields` field array to specify which fields will be updated.")
		g.P("// ```")
		for _, field := range allStr {
			g.P("// ", field)
		}
		g.P("// ```")
	}
	g.P("// Security:")
	g.P("//   Bearer:")
	g.P("// responses:")
	g.P("//   200: success")
	g.P("//   400: badRequest")
	g.P("//   403: forbidden")
	g.P("//   404: notFound")
}

func (g *GenMC2) generateService(file *generator.FileDescriptor, service *descriptor.ServiceDescriptorProto, serviceProps *ServiceProps) {
	if len(service.Method) == 0 {
		return
	}
	for ii, method := range service.Method {
		// path: 2 is method type
		methodPath := append(serviceProps.path, "2", strconv.Itoa(ii))
		g.generateMethod(file, *service.Name, method, methodPath, serviceProps)
	}
}

func (g *GenMC2) getMethodArgs(service string, method *descriptor.MethodDescriptorProto) *tmplArgs {
	api := GetMc2Api(method)
	if api == "" {
		return nil
	}
	apiVals := strings.Split(api, ",")
	if len(apiVals) != 3 {
		g.Fail(*method.Name, "invalid mc2_api string, expected ResourceType,Action,OrgNameField")
	}
	in := gensupport.GetDesc(g.Generator, method.GetInputType())
	out := gensupport.GetDesc(g.Generator, method.GetOutputType())
	g.support.FQTypeName(g.Generator, in)
	inname := *in.DescriptorProto.Name
	_, found := g.regionStructs[inname]
	args := &tmplArgs{
		Service:              service,
		MethodName:           *method.Name,
		InName:               inname,
		OutName:              *out.DescriptorProto.Name,
		GenStruct:            !found,
		Resource:             apiVals[0],
		Action:               apiVals[1],
		OrgField:             apiVals[2],
		Org:                  "obj." + apiVals[2],
		ShowOrg:              "res." + apiVals[2],
		OrgValid:             true,
		Outstream:            gensupport.ServerStreaming(method),
		StreamOutIncremental: gensupport.GetStreamOutIncremental(method),
		CustomAuthz:          GetMc2CustomAuthz(method),
		HasMethodArgs:        gensupport.HasMethodArgs(method),
		HasFields:            gensupport.HasGrpcFields(in.DescriptorProto),
		NotifyRoot:           GetMc2ApiNotifyroot(method),
		CustomValidateInput:  GetMc2CustomValidateInput(method),
	}
	if gensupport.GetMessageKey(in.DescriptorProto) != nil || gensupport.GetObjAndKey(in.DescriptorProto) {
		args.HasKey = true
	}
	if apiVals[2] == "" {
		args.Org = `""`
		args.ShowOrg = `""`
		args.OrgValid = false
	}
	if apiVals[2] == "skipenforce" {
		args.SkipEnforce = true
		args.OrgValid = false
	}
	if args.Action == "ActionView" && gensupport.IsShow(method) {
		args.Show = true
	}
	if !args.Outstream {
		args.ReturnErrArg = "nil, "
		args.Show = false
	}
	if !args.Show {
		args.TargetCloudlet = GetMc2TargetCloudlet(in.DescriptorProto)
		if args.TargetCloudlet != "" {
			args.TargetCloudletParam = ", targetCloudlet *edgeproto.CloudletKey"
			args.TargetCloudletArg = ", targetCloudlet"
			args.TargetCloudletFlag = strings.ReplaceAll(args.TargetCloudlet, ".", "")
		}
		args.OrgFieldFlag = strings.ReplaceAll(args.OrgField, ".", "")
	}
	authops := []string{}
	requiresOrg := GetMc2ApiRequiresOrg(method)
	if requiresOrg != "" && requiresOrg != "none" {
		authops = append(authops, "withRequiresOrg(obj."+requiresOrg+")")
	}
	usesOrg := GetUsesOrg(in.DescriptorProto)
	if usesOrg != "" && usesOrg != "none" && !args.CustomAuthz {
		prefix := gensupport.GetCamelCasePrefix(*method.Name)
		if prefix == "Create" {
			if requiresOrg == "" {
				g.Fail("method", *method.Name, "input", inname, "has uses_org and is a create operation, so method must have mc2_api_requires_org specified")
			}
		}
	}
	if len(authops) > 0 {
		args.AuthOps = ", " + strings.Join(authops, ", ")
	}
	if args.HasFields && strings.HasPrefix(*method.Name, "Update"+args.InName) {
		args.SetFields = true
	}
	if !found {
		g.regionStructs[args.InName] = struct{}{}
	}
	return args
}

func (g *GenMC2) generateMethod(file *generator.FileDescriptor, service string, method *descriptor.MethodDescriptorProto, methodPath []string, serviceProps *ServiceProps) {
	args := g.getMethodArgs(service, method)
	if args == nil {
		return
	}
	var tmpl *template.Template
	if g.genapi {
		tmpl = g.tmplApi
	} else if g.gentest {
		tmpl = g.tmplMethodTest
		g.importMctestclient = true
		g.importOrmtestutil = true
		g.importTesting = true
		g.importRequire = true
		g.importHttp = true
	} else if g.gentestutil {
		tmpl = g.tmplMethodTestutil
		g.importOrmapi = true
		g.importMctestclient = true
	} else if g.genctl {
		tmpl = g.tmplMethodCtl
		if serviceProps.cliusebase == "" {
			serviceProps.cliusebase = args.InName
		}
		// Remove the base name from the commands to avoid redundancy.
		cliuse := GetCliCmd(method)
		if cliuse == "" {
			cliuse = strings.Replace(*method.Name, serviceProps.cliusebase, "", 1)
		}
		cliuse = strings.ToLower(cliuse)
		if conflict, found := serviceProps.cliuses[cliuse]; found {
			g.Fail("Cli cmd name conflict between", cliuse, "(", *method.Name, ") and", cliuse, "(", conflict, "), please use protogen.cli_cmd option to avoid conflict")
		}
		serviceProps.cliuses[cliuse] = *method.Name
		args.CliUse = cliuse

		short := g.support.GetComments(file.GetName(), strings.Join(methodPath, ","))
		args.CliShort = strings.TrimSpace(strings.Map(gensupport.RemoveNewLines, short))
		if args.CliShort == "" {
			g.Fail("method", *method.Name, "in file", file.GetName(), "needs a comment")
		}
		in := gensupport.GetDesc(g.Generator, method.GetInputType())
		args.NoConfig = gensupport.GetNoConfig(in.DescriptorProto, method)
		g.importOrmapi = true
		g.importStrings = true
	} else if g.genctrlclient {
		in := gensupport.GetDesc(g.Generator, method.GetInputType())
		args.TargetCloudlet = GetMc2TargetCloudlet(in.DescriptorProto)
		tmpl = g.tmplCtrlClient
		g.importContext = true
		g.importLog = true
		g.importOrmutil = true
		if args.Outstream {
			g.importIO = true
		}
	} else {
		tmpl = g.tmpl
		g.importEcho = true
		g.importOrmapi = true
		g.importLog = true
		g.importOrmutil = true
		g.importCtrlClient = true
		if args.Outstream {
		} else {
			g.importGrpcStatus = true
		}
	}
	err := tmpl.Execute(g, &args)
	if err != nil {
		g.Fail("Failed to execute template %s: ", tmpl.Name(), err.Error())
	}
}

type tmplArgs struct {
	Service              string
	MethodName           string
	InName               string
	OutName              string
	GenStruct            bool
	Resource             string
	Action               string
	OrgField             string
	Org                  string
	OrgFieldFlag         string
	ShowOrg              string
	OrgValid             bool
	Outstream            bool
	SkipEnforce          bool
	Show                 bool
	StreamOutIncremental bool
	NoConfig             string
	ReturnErrArg         string
	SetFields            bool
	HasFields            bool
	CustomAuthz          bool
	TargetCloudlet       string
	TargetCloudletParam  string
	TargetCloudletArg    string
	TargetCloudletFlag   string
	HasMethodArgs        bool
	NotifyRoot           bool
	AuthOps              string
	HasKey               bool
	CliUse               string
	CliShort             string
	CliGroup             string
	CustomValidateInput  bool
}

var tmplApi = `
// Request summary for {{.MethodName}}
// swagger:parameters {{.MethodName}}
type swagger{{.MethodName}} struct {
	// in: body
	Body Region{{.InName}}
}

{{- if .GenStruct}}

type Region{{.InName}} struct {
	// Region name
        // required: true
	Region string
	// {{.InName}} in region
	{{.InName}} edgeproto.{{.InName}}
}

func (s *Region{{.InName}}) GetRegion() string {
	return s.Region
}

func (s *Region{{.InName}}) GetObj() interface{} {
	return &s.{{.InName}}
}

func (s *Region{{.InName}}) GetObjName() string {
	return "{{.InName}}"
}

{{- if .HasFields}}
func (s *Region{{.InName}}) GetObjFields() []string {
	return s.{{.InName}}.Fields
}

func (s *Region{{.InName}}) SetObjFields(fields []string) {
	s.{{.InName}}.Fields = fields
}

{{- end}}
{{- end}}
`

var tmpl = `
func {{.MethodName}}(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.Region{{.InName}}{}
{{- if .SetFields}}
	dat, err := ReadConn(c, &in)
{{- else}}
	_, err = ReadConn(c, &in)
{{- end}}
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
{{- if .HasKey}}
	log.SetTags(span, in.{{.InName}}.GetKey().GetTags())
{{- end}}
{{- if .OrgValid}}
	span.SetTag("org", in.{{.InName}}.{{.OrgField}})
{{- end}}
{{- if .SetFields}}
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}
{{- end}}

	obj := &in.{{.InName}}
{{- if (not .Show)}}
	{{- /* don't set tags for show because create/etc may call shows, which end up adding unnecessary blank tags */}}
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
{{- end}}
{{- if (ne .Action "ActionView")}}
	if err := obj.IsValidArgsFor{{.MethodName}}(); err != nil {
		return err
	}
{{- end}}
{{- if (not .SkipEnforce)}}
{{- if and .Show .CustomAuthz}}
	var authz ctrlclient.{{.MethodName}}Authz
	if !rc.SkipAuthz {
		authz, err = new{{.MethodName}}Authz(ctx, rc.Region, rc.Username, {{.Resource}}, {{.Action}})
		if err != nil {
			return err
		}
	}
{{- else if and .Show (not .CustomAuthz)}}
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, {{.Resource}}, {{.Action}})
		if err != nil {
			return err
		}
	}
{{- else if .CustomAuthz}}
	if !rc.SkipAuthz {
		if err := authz{{.MethodName}}(ctx, rc.Region, rc.Username, obj,
			{{.Resource}}, {{.Action}}); err != nil {
			return err
		}
	}
{{- else}}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, {{.Org}},
			{{.Resource}}, {{.Action}}{{.AuthOps}}); err != nil {
			return err
		}
	}
{{- end}}
{{- end}}
{{- if .TargetCloudlet}}
       // Need access to database for federation handling
       rc.Database = database
{{- end}}
{{if .Outstream}}
	cb := func(res *edgeproto.{{.OutName}}) error {
                payload := ormapi.StreamPayload{}
                payload.Data = res
                return WriteStream(c, &payload)
        }
{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
	err = ctrlclient.{{.MethodName}}Stream(ctx, rc, obj, connCache, authz, cb)
{{- else if and (and (not .SkipEnforce) .Show) (not .CustomAuthz)}}
	err = ctrlclient.{{.MethodName}}Stream(ctx, rc, obj, connCache, authz, cb)
{{- else}}
	err = ctrlclient.{{.MethodName}}Stream(ctx, rc, obj, connCache, cb)
{{- end}}
	if err != nil {
		return err
	}
	return nil
{{- else}}
{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
	resp, err := ctrlclient.{{.MethodName}}Obj(ctx, rc , obj, connCache, authz)
{{- else if and (and (not .SkipEnforce) .Show) (not .CustomAuthz)}}
	resp, err := ctrlclient.{{.MethodName}}Obj(ctx, rc , obj, connCache, authz)
{{- else}}
	resp, err := ctrlclient.{{.MethodName}}Obj(ctx, rc, obj, connCache)
{{- end}}
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
{{- end}}
}

`

var tmplCtrlClient = `
{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
type {{.MethodName}}Authz interface {
        Ok(obj *edgeproto.{{.OutName}}) (bool, bool)
        Filter(obj *edgeproto.{{.OutName}})
}
{{- end}}

{{if .Outstream}}
{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
func {{.MethodName}}Stream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr, authz {{.MethodName}}Authz, cb func(res *edgeproto.{{.OutName}}) error) error {
{{- else if and (and (not .SkipEnforce) .Show) (not .CustomAuthz)}}
func {{.MethodName}}Stream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.{{.OutName}}) error) error {
{{- else}}
func {{.MethodName}}Stream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr, cb func(res *edgeproto.{{.OutName}}) error) error {
{{- end}}
{{- else}}
{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
func {{.MethodName}}Obj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr, authz {{.MethodName}}Authz) (*edgeproto.{{.OutName}}, error) {
{{- else if and (and (not .SkipEnforce) .Show) (not .CustomAuthz)}}
func {{.MethodName}}Obj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr, authz authzShow) (*edgeproto.{{.OutName}}, error) {
{{- else}}
func {{.MethodName}}Obj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.{{.InName}}, connObj ClientConnMgr) (*edgeproto.{{.OutName}}, error) {
{{- end}}
{{- end}}
{{- if .CustomValidateInput}}
	if err := {{.MethodName}}ValidateInput(ctx, rc, obj); err != nil {
		return {{.ReturnErrArg}}err
	}
{{- end}}
{{- if .NotifyRoot}}
        conn, err := connObj.GetNotifyRootConn(ctx)
{{- else}}
        conn, err := connObj.GetRegionConn(ctx, rc.Region)
{{- end}}
        if err != nil {
                return {{.ReturnErrArg}}err
        }
        api := edgeproto.New{{.Service}}Client(conn)
        log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
        defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
{{- if .Outstream}}
        stream, err := api.{{.MethodName}}(ctx, obj)
        if err != nil {
                return {{.ReturnErrArg}}err
        }
        for {
                res, err := stream.Recv()
                if err == io.EOF {
                        err = nil
                        break
                }
                if err != nil {
                        return {{.ReturnErrArg}}err
                }
{{- if and .Show (not .SkipEnforce)}}
                if !rc.SkipAuthz {
                        if authz != nil {
{{- if .CustomAuthz}}
{{- if .Show }}
                                authzOk, filterOutput := authz.Ok(res)
                                if !authzOk {
{{- else }}
                                if !authz.Ok(res) {
{{- end}}
                                        continue
                                }
{{- if .Show }}
                                if filterOutput {
                                        authz.Filter(res)
                                }
{{- end}}
{{- else}}
                                if !authz.Ok({{.ShowOrg}}) {
                                        continue
                                }
{{- end}}
                        }
                }
{{- end}}
                err = cb(res)
                if err != nil {
                        return {{.ReturnErrArg}}err
                }
        }
        return {{.ReturnErrArg}}nil
{{- else}}
        return api.{{.MethodName}}(ctx, obj)
{{- end}}
}

`

var tmplMethodTestutil = `
{{- if .Outstream}}
func Test{{.MethodName}}(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.{{.InName}}, modFuncs ...func(*edgeproto.{{.InName}})) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func Test{{.MethodName}}(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.{{.InName}}, modFuncs ...func(*edgeproto.{{.InName}})) (*edgeproto.{{.OutName}}, int, error) {
{{- end}}
	dat := &ormapi.Region{{.InName}}{}
	dat.Region = region
	dat.{{.InName}} = *in
	for _, fn := range modFuncs {
		fn(&dat.{{.InName}})
	}
	return mcClient.{{.MethodName}}(uri, token, dat)
}

{{- if .Outstream}}
func TestPerm{{.MethodName}}(mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func TestPerm{{.MethodName}}(mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) (*edgeproto.{{.OutName}}, int, error) {
{{- end}}
	in := &edgeproto.{{.InName}}{}
{{- if .TargetCloudlet}}
	if targetCloudlet != nil {
		in.{{.TargetCloudlet}} = *targetCloudlet
{{- if .SetFields}}
		in.Fields = append(in.Fields,
			edgeproto.{{.InName}}Field{{.TargetCloudletFlag}}Name,
			edgeproto.{{.InName}}Field{{.TargetCloudletFlag}}Organization,
		)
{{- end}}
	}
{{- end}}
{{- if and (ne .OrgField "") (not .SkipEnforce)}}
	in.{{.OrgField}} = org
{{- if .SetFields}}
	in.Fields = append(in.Fields, edgeproto.{{.InName}}Field{{.OrgFieldFlag}})
{{- end}}
{{- end}}
	return Test{{.MethodName}}(mcClient, uri, token, region, in, modFuncs...)
}
`

var tmplMethodTest = `

var _ = edgeproto.GetFields

func badPerm{{.MethodName}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func bad{{.MethodName}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, st, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPerm{{.MethodName}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegion{{.MethodName}}(t *testing.T, mcClient *mctestclient.Client, uri, token, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	out, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
{{- if .Show}}
	require.Equal(t, 0, len(out))
{{- else}}
	_ = out
{{- end}}
}
`

var tmplMethodCtl = `
var {{.MethodName}}Cmd = &ApiCommand{
	Name: "{{.MethodName}}",
	Use: "{{.CliUse}}",
	Short: "{{.CliShort}}",
{{- if .Show}}
{{- if not .NotifyRoot}}
	RequiredArgs: "region",
{{- end}}
	OptionalArgs: strings.Join(append({{.InName}}RequiredArgs, {{.InName}}OptionalArgs...), " "),
{{- else if .HasMethodArgs}}
	RequiredArgs: {{if not .NotifyRoot}}"region " + {{end}}strings.Join({{.MethodName}}RequiredArgs, " "),
	OptionalArgs: strings.Join({{.MethodName}}OptionalArgs, " "),
{{- else}}
	RequiredArgs: {{if not .NotifyRoot}}"region " + {{end}}strings.Join({{.InName}}RequiredArgs, " "),
	OptionalArgs: strings.Join({{.InName}}OptionalArgs, " "),
{{- end}}
	AliasArgs: strings.Join({{.InName}}AliasArgs, " "),
	SpecialArgs: &{{.InName}}SpecialArgs,
	Comments: addRegionComment({{.InName}}Comments),
{{- if .NoConfig}}
	NoConfig: "{{.NoConfig}}",
{{- end}}
	ReqData: &ormapi.Region{{.InName}}{},
	ReplyData: &edgeproto.{{.OutName}}{},
	Path: "/auth/ctrl/{{.MethodName}}",
{{- if .Outstream}}
	StreamOut: true,
{{- end}}
{{- if .StreamOutIncremental}}
	StreamOutIncremental: true,
{{- end}}
	ProtobufApi: true,
}
`

func (g *GenMC2) generateTestApi(service *descriptor.ServiceDescriptorProto) {
	// group methods by input type
	groups := gensupport.GetMethodGroups(g.Generator, service)
	for _, group := range groups {
		g.generateTestGroupApi(service, group)
	}
}

func (g *GenMC2) generateTestGroupApi(service *descriptor.ServiceDescriptorProto, group *gensupport.MethodGroup) {
	if !group.HasMc2Api {
		return
	}
	message := group.In.DescriptorProto
	msgInfo, found := g.inputMessages[*message.Name]
	if !found {
		return
	}

	args := msgArgs{
		Message:        group.InType,
		TargetCloudlet: GetMc2TargetCloudlet(message),
	}
	if len(msgInfo.Services) > 1 {
		// avoid name conflicts if the same message type is used
		// as inputs in different service apis.
		args.Prefix = *service.Name
	}
	for _, info := range group.MethodInfos {
		methodArgs := g.getMethodArgs(*service.Name, info.Method)
		if methodArgs == nil {
			continue
		}
		if methodArgs.Show {
			args.MethodArgsShow = append(args.MethodArgsShow, *methodArgs)
		} else {
			args.MethodArgsNoShow = append(args.MethodArgsNoShow, *methodArgs)
		}
	}
	// make sure create is first and delete is last to avoid
	// extra objects being created by test perm funcs.
	sort.Sort(sortByMethodName(args.MethodArgsNoShow))

	if args.TargetCloudlet != "" {
		args.TargetCloudletParam = ", targetCloudlet *edgeproto.CloudletKey"
		args.TargetCloudletArg = ", targetCloudlet"
	}
	err := g.tmplMessageTest.Execute(g, &args)
	if err != nil {
		g.Fail("Failed to execute message test template: ", err.Error())
	}
	g.importTesting = true
	g.importRequire = true
	g.importHttp = true
}

type sortByMethodName []tmplArgs

func (s sortByMethodName) Len() int      { return len(s) }
func (s sortByMethodName) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortByMethodName) Less(i, j int) bool {
	if strings.HasPrefix(s[i].MethodName, "Create") || strings.HasPrefix(s[j].MethodName, "Delete") {
		return true
	}
	if strings.HasPrefix(s[j].MethodName, "Create") || strings.HasPrefix(s[i].MethodName, "Delete") {
		return false
	}
	return false
}

func (g *GenMC2) generateRunApi(file *descriptor.FileDescriptorProto, service *descriptor.ServiceDescriptorProto) {
	// group methods by input type
	groups := gensupport.GetMethodGroups(g.Generator, service)
	for _, group := range groups {
		g.generateRunGroupApi(file, service, group)
	}
}

func (g *GenMC2) generateRunGroupApi(file *descriptor.FileDescriptorProto, service *descriptor.ServiceDescriptorProto, group *gensupport.MethodGroup) {
	for _, info := range group.MethodInfos {
		inType := group.InType
		pkg := g.support.GetPackage(group.In)
		outPkg := g.support.GetPackage(info.Out)
		outType := outPkg + info.OutType
		if info.Stream {
			outType = "[]" + outType
		} else {
			outType = "*" + outType
		}
		g.importContext = true
		g.P()
		g.P("func (s *TestClient) ", info.Name, "(ctx context.Context, in *", pkg, inType, ") (", outType, ", error) {")
		if !info.Mc2Api {
			g.P("return nil, nil")
			g.P("}")
			g.P()
			continue
		}
		g.P("inR := &ormapi.Region", inType, "{")
		g.P("Region: s.Region,")
		g.P(inType, ": *in,")
		g.P("}")
		g.P("out, status, err := s.McClient.", info.Name, "(s.Uri, s.Token, inR)")
		g.P("if err == nil && status != 200 {")
		g.P("err = fmt.Errorf(\"status: %d\\n\", status)")
		g.P("}")
		if group.SingularData && info.IsShow {
			// Singular data show will return forbidden
			// if no permissions, instead of just an empty list.
			// For testing, ignore this error.
			g.P("if status == 403 {")
			g.P("err = nil")
			g.P("}")
		}
		g.P("return out, err")
		g.P("}")
	}
}

type msgArgs struct {
	Prefix              string
	Message             string
	TargetCloudlet      string
	TargetCloudletParam string
	TargetCloudletArg   string
	MethodArgsNoShow    []tmplArgs
	MethodArgsShow      []tmplArgs
}

var tmplMessageTest = `
{{- if .MethodArgsNoShow}}
// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTest{{.Prefix}}{{.Message}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.Message}})) {
{{- range .MethodArgsNoShow}}
	badPerm{{.MethodName}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
{{- end}}
}
{{- end}}

{{- if .MethodArgsShow}}
func badPermTestShow{{.Prefix}}{{.Message}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
{{- range $i, $e := .MethodArgsShow}}
	list{{$i}}, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list{{$i}}))
{{- end}}
}
{{- end}}

{{- if or .MethodArgsNoShow .MethodArgsShow}}
// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTest{{.Prefix}}{{.Message}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, showcount int, modFuncs ...func(*edgeproto.{{.Message}})) {
{{- range .MethodArgsNoShow}}
	goodPerm{{.MethodName}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
{{- end}}
{{- if .MethodArgsShow}}
	goodPermTestShow{{.Prefix}}{{.Message}}(t, mcClient, uri, token, region, org, showcount)
{{- end}}
	// make sure region check works
{{- range .MethodArgsNoShow}}
	badRegion{{.MethodName}}(t, mcClient, uri, token, org{{.TargetCloudletArg}}, modFuncs...)
{{- end}}
}
{{- end}}

{{- if .MethodArgsShow}}
func goodPermTestShow{{.Prefix}}{{.Message}}(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
{{- range $i, $e := .MethodArgsShow}}
	list{{$i}}, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list{{$i}}))

	badRegion{{.MethodName}}(t, mcClient, uri, token, org{{.TargetCloudletArg}})
{{- end}}
}
{{- end}}

{{- if or .MethodArgsNoShow .MethodArgsShow}}
// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTest{{.Prefix}}{{.Message}}(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string{{.TargetCloudletParam}}, showcount int, modFuncs ...func(*edgeproto.{{.Message}})) {
{{- if .MethodArgsNoShow}}
	badPermTest{{.Prefix}}{{.Message}}(t, mcClient, uri, token1, region, org2{{.TargetCloudletArg}}, modFuncs...)
	badPermTest{{.Prefix}}{{.Message}}(t, mcClient, uri, token2, region, org1{{.TargetCloudletArg}}, modFuncs...)
{{- end}}
{{- if .MethodArgsShow}}
	badPermTestShow{{.Prefix}}{{.Message}}(t, mcClient, uri, token1, region, org2)
	badPermTestShow{{.Prefix}}{{.Message}}(t, mcClient, uri, token2, region, org1)
{{- end}}
	goodPermTest{{.Prefix}}{{.Message}}(t, mcClient, uri, token1, region, org1{{.TargetCloudletArg}}, showcount, modFuncs...)
	goodPermTest{{.Prefix}}{{.Message}}(t, mcClient, uri, token2, region, org2{{.TargetCloudletArg}}, showcount, modFuncs...)
}
{{- end}}
`

func (g *GenMC2) generateCtlGroup(service *descriptor.ServiceDescriptorProto, methodGroups map[string]*gensupport.MethodGroup) {
	if !hasMc2Api(service) {
		return
	}
	g.P("var ", service.Name, "Cmds = []*ApiCommand{")
	for _, method := range service.Method {
		if GetMc2Api(method) == "" {
			continue
		}
		g.P(method.Name, "Cmd,")
	}
	g.P("}")
	g.P()
	serviceName := strings.TrimSuffix(*service.Name, "Api")
	plural := "s"
	if strings.HasSuffix(serviceName, "s") {
		plural = ""
	}
	g.P("const ", serviceName, "Group = \"", serviceName, "\"")
	g.P()
	g.P("func init() {")
	g.P("AllApis.AddGroup(", serviceName, "Group, \"Manage ", serviceName, plural, "\", ", service.Name, "Cmds)")
	g.P("}")
	g.P()
	for ii, method := range service.Method {
		gensupport.GenerateMethodArgs(g.Generator, &g.support, method, methodGroups, true, ii)
	}
}

func getCliGroup(serviceName string) string {
	serviceName = strings.TrimSuffix(serviceName, "Api")
	return strings.ToLower(serviceName)
}

func hasMc2Api(service *descriptor.ServiceDescriptorProto) bool {
	if len(service.Method) == 0 {
		return false
	}
	for _, method := range service.Method {
		if GetMc2Api(method) != "" {
			return true
		}
	}
	return false
}

func (g *GenMC2) hasParam(p string) bool {
	_, found := g.Generator.Param[p]
	return found
}

func GetMc2Api(method *descriptor.MethodDescriptorProto) string {
	return gensupport.GetStringExtension(method.Options, protogen.E_Mc2Api, "")
}

func GetMc2ApiRequiresOrg(method *descriptor.MethodDescriptorProto) string {
	return gensupport.GetStringExtension(method.Options, protogen.E_Mc2ApiRequiresOrg, "")
}

func GetMc2CustomAuthz(method *descriptor.MethodDescriptorProto) bool {
	return proto.GetBoolExtension(method.Options, protogen.E_Mc2CustomAuthz, false)
}

func GetMc2ApiNotifyroot(method *descriptor.MethodDescriptorProto) bool {
	return proto.GetBoolExtension(method.Options, protogen.E_Mc2ApiNotifyroot, false)
}

func GetMc2CustomValidateInput(method *descriptor.MethodDescriptorProto) bool {
	return proto.GetBoolExtension(method.Options, protogen.E_Mc2CustomValidateInput, false)
}

func GetCliCmd(method *descriptor.MethodDescriptorProto) string {
	return gensupport.GetStringExtension(method.Options, protogen.E_CliCmd, "")
}

func GetMc2TargetCloudlet(message *descriptor.DescriptorProto) string {
	return gensupport.GetStringExtension(message.Options, protogen.E_Mc2TargetCloudlet, "")
}

func GetGenerateCudTest(message *descriptor.DescriptorProto) bool {
	return proto.GetBoolExtension(message.Options, protogen.E_GenerateCudTest, false)
}

func GetGenerateShowTest(message *descriptor.DescriptorProto) bool {
	return proto.GetBoolExtension(message.Options, protogen.E_GenerateShowTest, false)
}

func GetGenerateCudTestUpdate(message *descriptor.DescriptorProto) bool {
	return proto.GetBoolExtension(message.Options, protogen.E_GenerateCudTestUpdate, true)
}

func GetGenerateAddrmTest(message *descriptor.DescriptorProto) bool {
	return proto.GetBoolExtension(message.Options, protogen.E_GenerateAddrmTest, false)
}

func GetUsesOrg(message *descriptor.DescriptorProto) string {
	return gensupport.GetStringExtension(message.Options, protogen.E_UsesOrg, "")
}

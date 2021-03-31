package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
	"github.com/gogo/protobuf/protoc-gen-gogo/generator"
	"github.com/mobiledgex/edge-cloud/gensupport"
	"github.com/mobiledgex/edge-cloud/protogen"
)

type GenMC2 struct {
	*generator.Generator
	support              gensupport.PluginSupport
	tmpl                 *template.Template
	tmplApi              *template.Template
	tmplMethodTest       *template.Template
	tmplMethodTestutil   *template.Template
	tmplMethodCtl        *template.Template
	tmplMessageTest      *template.Template
	tmplMethodClient     *template.Template
	tmplMethodCliWrapper *template.Template
	regionStructs        map[string]struct{}
	firstFile            bool
	genapi               bool
	gentest              bool
	gentestutil          bool
	genclient            bool
	genctl               bool
	gencliwrapper        bool
	importEcho           bool
	importHttp           bool
	importContext        bool
	importIO             bool
	importOS             bool
	importJson           bool
	importTesting        bool
	importRequire        bool
	importOrmclient      bool
	importOrmapi         bool
	importOrmtestutil    bool
	importGrpcStatus     bool
	importStrings        bool
	importLog            bool
	importCli            bool
}

func (g *GenMC2) Name() string {
	return "GenMC2"
}

func (g *GenMC2) Init(gen *generator.Generator) {
	g.Generator = gen
	g.tmpl = template.Must(template.New("mc2").Parse(tmpl))
	g.tmplApi = template.Must(template.New("mc2api").Parse(tmplApi))
	g.tmplMethodTest = template.Must(template.New("methodtest").Parse(tmplMethodTest))
	g.tmplMethodTestutil = template.Must(template.New("methodtest").Parse(tmplMethodTestutil))
	g.tmplMethodClient = template.Must(template.New("methodclient").Parse(tmplMethodClient))
	g.tmplMethodCtl = template.Must(template.New("methodctl").Parse(tmplMethodCtl))
	g.tmplMethodCliWrapper = template.Must(template.New("methodcliwrapper").Parse(tmplMethodCliWrapper))
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
		g.PrintImport("", "github.com/mobiledgex/edge-cloud/log")
	}
	if g.importOrmclient {
		g.PrintImport("", "github.com/mobiledgex/edge-cloud-infra/mc/ormclient")
	}
	if g.importOrmapi {
		g.PrintImport("", "github.com/mobiledgex/edge-cloud-infra/mc/ormapi")
	}
	if g.importOrmtestutil {
		g.PrintImport("", "github.com/mobiledgex/edge-cloud-infra/mc/orm/testutil")
	}
	if g.importCli {
		g.PrintImport("", "github.com/mobiledgex/edge-cloud/cli")
	}
	if g.importGrpcStatus {
		g.PrintImport("", "google.golang.org/grpc/status")
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
	g.importOrmclient = false
	g.importOrmapi = false
	g.importOrmtestutil = false
	g.importGrpcStatus = false
	g.importLog = false
	g.importCli = false

	g.support.InitFile()
	if !g.support.GenFile(*file.FileDescriptorProto.Name) {
		return
	}
	g.genapi = g.hasParam("genapi")
	g.gentest = g.hasParam("gentest")
	g.gentestutil = g.hasParam("gentestutil")
	g.genclient = g.hasParam("genclient")
	g.genctl = g.hasParam("genctl")
	g.gencliwrapper = g.hasParam("gencliwrapper")
	if !g.genFile(file) {
		return
	}

	g.P(gensupport.AutoGenComment)

	for ii, service := range file.FileDescriptorProto.Service {
		serviceProps := ServiceProps{}
		serviceProps.Init(ii)
		g.generateService(file, service, &serviceProps)
		if g.genclient {
			g.generateClientInterface(service)
		}
		if g.genctl {
			g.generateCtlGroup(service)
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
			gensupport.GenerateMessageArgs(g.Generator, &g.support, msg, true, ii)
		}
	}

	if g.genapi || g.genclient || g.genctl || g.gencliwrapper || g.gentestutil {
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

func (g *GenMC2) generateMethod(file *generator.FileDescriptor, service string, method *descriptor.MethodDescriptorProto, methodPath []string, serviceProps *ServiceProps) {
	api := GetMc2Api(method)
	if api == "" {
		return
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
	args := tmplArgs{
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
		NotifyRoot:           GetMc2ApiNotifyroot(method),
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
		}
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
	if g.genctl || g.gencliwrapper {
		if serviceProps.cliusebase == "" {
			serviceProps.cliusebase = inname
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
	}

	var tmpl *template.Template
	if g.genapi {
		tmpl = g.tmplApi
	} else if g.genclient {
		tmpl = g.tmplMethodClient
		g.importOrmapi = true
	} else if g.gentest {
		tmpl = g.tmplMethodTest
		g.importOrmclient = true
		g.importOrmtestutil = true
		g.importTesting = true
		g.importRequire = true
		g.importHttp = true
	} else if g.gentestutil {
		tmpl = g.tmplMethodTestutil
		g.importOrmapi = true
		g.importOrmclient = true
	} else if g.genctl {
		tmpl = g.tmplMethodCtl
		short := g.support.GetComments(file.GetName(), strings.Join(methodPath, ","))
		args.CliShort = strings.TrimSpace(strings.Map(gensupport.RemoveNewLines, short))
		if args.CliShort == "" {
			g.Fail("method", *method.Name, "in file", file.GetName(), "needs a comment")
		}
		g.importOrmapi = true
		g.importStrings = true
		g.importCli = true
		if strings.HasPrefix(*method.Name, "Update"+args.InName) && gensupport.HasGrpcFields(in.DescriptorProto) {
			args.SetFields = true
		}
	} else if g.gencliwrapper {
		tmpl = g.tmplMethodCliWrapper
		args.NoConfig = gensupport.GetNoConfig(in.DescriptorProto, method)
		args.CliGroup = getCliGroup(service)
		g.importOrmapi = true
		g.importStrings = true
	} else {
		tmpl = g.tmpl
		g.importEcho = true
		g.importContext = true
		g.importOrmapi = true
		g.importLog = true
		if args.Outstream {
			g.importIO = true
		} else {
			g.importGrpcStatus = true
		}
	}
	err := tmpl.Execute(g, &args)
	if err != nil {
		g.Fail("Failed to execute template %s: ", tmpl.Name(), err.Error())
	}
	if !found {
		g.regionStructs[inname] = struct{}{}
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
	ShowOrg              string
	OrgValid             bool
	Outstream            bool
	SkipEnforce          bool
	Show                 bool
	StreamOutIncremental bool
	NoConfig             string
	ReturnErrArg         string
	SetFields            bool
	CustomAuthz          bool
	TargetCloudlet       string
	TargetCloudletParam  string
	TargetCloudletArg    string
	HasMethodArgs        bool
	NotifyRoot           bool
	AuthOps              string
	HasKey               bool
	CliUse               string
	CliShort             string
	CliGroup             string
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
        // required: true
	// Region name
	Region string
	{{.InName}} edgeproto.{{.InName}}
}

{{- end}}
`

var tmpl = `
func {{.MethodName}}(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.Region{{.InName}}{}
{{- if .Outstream}}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
{{- else}}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
{{- end}}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
{{- if .HasKey}}
	log.SetTags(span, in.{{.InName}}.GetKey().GetTags())
{{- end}}
{{- if .OrgValid}}
	span.SetTag("org", in.{{.InName}}.{{.OrgField}})
{{- end}}
{{- if .Outstream}}

	err = {{.MethodName}}Stream(ctx, rc, &in.{{.InName}}, func(res *edgeproto.{{.OutName}}) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
{{- else}}
	resp, err := {{.MethodName}}Obj(ctx, rc, &in.{{.InName}})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
{{- end}}
}

{{- if and (not .SkipEnforce) (and .Show .CustomAuthz)}}
type {{.MethodName}}Authz interface {
	Ok(obj *edgeproto.{{.InName}}) (bool, bool)
	Filter(obj *edgeproto.{{.InName}})
}
{{- end}}

{{if .Outstream}}
func {{.MethodName}}Stream(ctx context.Context, rc *RegionContext, obj *edgeproto.{{.InName}}, cb func(res *edgeproto.{{.OutName}})) error {
{{- else}}
func {{.MethodName}}Obj(ctx context.Context, rc *RegionContext, obj *edgeproto.{{.InName}}) (*edgeproto.{{.OutName}}, error) {
{{- end}}
{{- if (not .Show)}}
	{{- /* don't set tags for show because create/etc may call shows, which end up adding unnecessary blank tags */}}
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
{{- end}}
{{- if (ne .Action "ActionView")}}
	if err := obj.IsValidArgsFor{{.MethodName}}(); err != nil {
		return {{.ReturnErrArg}}err
	}
{{- end}}
{{- if (not .SkipEnforce)}}
{{- if and .Show .CustomAuthz}}
	var authz {{.MethodName}}Authz
	var err error
	if !rc.skipAuthz {
		authz, err = new{{.MethodName}}Authz(ctx, rc.region, rc.username, {{.Resource}}, {{.Action}})
		if err != nil {
			return {{.ReturnErrArg}}err
		}
	}
{{- else if and .Show (not .CustomAuthz)}}
	var authz *AuthzShow
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAuthz(ctx, rc.region, rc.username, {{.Resource}}, {{.Action}})
		if err != nil {
			return {{.ReturnErrArg}}err
		}
	}
{{- else if .CustomAuthz}}
	if !rc.skipAuthz {
		if err := authz{{.MethodName}}(ctx, rc.region, rc.username, obj,
			{{.Resource}}, {{.Action}}); err != nil {
			return {{.ReturnErrArg}}err
		}
	}
{{- else}}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, {{.Org}},
			{{.Resource}}, {{.Action}}{{.AuthOps}}); err != nil {
			return {{.ReturnErrArg}}err
		}
	}
{{- end}}
{{- end}}
	if rc.conn == nil {
{{- if .NotifyRoot}}
		conn, err := connectNotifyRoot(ctx)
{{- else}}
		conn, err := connectController(ctx, rc.region)
{{- end}}
		if err != nil {
			return {{.ReturnErrArg}}err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.New{{.Service}}Client(rc.conn)
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
		if !rc.skipAuthz {
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
{{- end}}
		cb(res)
	}
	return nil
{{- else}}
	return api.{{.MethodName}}(ctx, obj)
{{- end}}
}

{{ if .Outstream}}
func {{.MethodName}}Obj(ctx context.Context, rc *RegionContext, obj *edgeproto.{{.InName}}) ([]edgeproto.{{.OutName}}, error) {
	arr := []edgeproto.{{.OutName}}{}
	err := {{.MethodName}}Stream(ctx, rc, obj, func(res *edgeproto.{{.OutName}}) {
		arr = append(arr, *res)
	})
	return arr, err
}
{{- end}}

`

var tmplMethodTestutil = `
{{- if .Outstream}}
func Test{{.MethodName}}(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.{{.InName}}, modFuncs ...func(*edgeproto.{{.InName}})) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func Test{{.MethodName}}(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.{{.InName}}, modFuncs ...func(*edgeproto.{{.InName}})) (*edgeproto.{{.OutName}}, int, error) {
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
func TestPerm{{.MethodName}}(mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func TestPerm{{.MethodName}}(mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) (*edgeproto.{{.OutName}}, int, error) {
{{- end}}
	in := &edgeproto.{{.InName}}{}
{{- if .TargetCloudlet}}
	if targetCloudlet != nil {
		in.{{.TargetCloudlet}} = *targetCloudlet
	}
{{- end}}
{{- if and (ne .OrgField "") (not .SkipEnforce)}}
	in.{{.OrgField}} = org
{{- end}}
	return Test{{.MethodName}}(mcClient, uri, token, region, in, modFuncs...)
}
`

var tmplMethodTest = `

var _ = edgeproto.GetFields

func badPerm{{.MethodName}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func bad{{.MethodName}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, status int{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, st, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPerm{{.MethodName}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.InName}})) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}
`

var tmplMethodClient = `
{{- if .Outstream}}
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) ([]edgeproto.{{.OutName}}, int, error) {
	out := edgeproto.{{.OutName}}{}
	outlist := []edgeproto.{{.OutName}}{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/{{.MethodName}}", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}
{{- else}}
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) (*edgeproto.{{.OutName}}, int, error) {
	out := edgeproto.{{.OutName}}{}
	status, err := s.PostJson(uri+"/auth/ctrl/{{.MethodName}}", token, in, &out)
	if err != nil {
		return nil, status, err
	}
	return &out, status, err
}
{{- end}}
`

var tmplMethodCtl = `
var {{.MethodName}}Cmd = &cli.Command{
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
	ReqData: &ormapi.Region{{.InName}}{},
	ReplyData: &edgeproto.{{.OutName}}{},
	Run: runRest("/auth/ctrl/{{.MethodName}}",
{{- if .SetFields}}
		withSetFieldsFunc(set{{.MethodName}}Fields),
{{- end}}
	),
{{- if .Outstream}}
	StreamOut: true,
{{- end}}
{{- if .StreamOutIncremental}}
	StreamOutIncremental: true,
{{- end}}
}

{{if .SetFields}}
func set{{.MethodName}}Fields(in map[string]interface{}) {
	// get map for edgeproto object in region struct
	obj := in[strings.ToLower("{{.InName}}")]
	if obj == nil {
		return
	}
	objmap, ok := obj.(map[string]interface{})
	if !ok {
		return
	}
	fields := cli.GetSpecifiedFields(objmap, &edgeproto.{{.InName}}{}, cli.JsonNamespace)
	// include fields already specified
	if inFields, found := objmap["fields"]; found {
		if fieldsArr, ok := inFields.([]string); ok {
			fields = append(fields, fieldsArr...)
		}
	}
	objmap["fields"] = fields
}
{{- end}}

`

var tmplMethodCliWrapper = `
{{- if .Outstream}}
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) ([]edgeproto.{{.OutName}}, int, error) {
	args := []string{"{{.CliGroup}}", "{{.CliUse}}"}
	outlist := []edgeproto.{{.OutName}}{}
	noconfig := strings.Split("{{.NoConfig}}", ",")
	ops := []runOp{
		withIgnore(noconfig),
{{- if .StreamOutIncremental}}
		withStreamOutIncremental(),
{{- end}}
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}
{{- else}}
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) (*edgeproto.{{.OutName}}, int, error) {
	args := []string{"{{.CliGroup}}", "{{.CliUse}}"}
	out := edgeproto.{{.OutName}}{}
	noconfig := strings.Split("{{.NoConfig}}", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}
{{- end}}

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
	if !GetGenerateCudTest(message) || GetGenerateShowTest(message) {
		return
	}

	args := msgArgs{
		Message:        group.InType,
		HasUpdate:      GetGenerateCudTestUpdate(message),
		TargetCloudlet: GetMc2TargetCloudlet(message),
	}
	if GetGenerateAddrmTest(message) {
		args.Create = "Add"
		args.Delete = "Remove"
	} else {
		args.Create = "Create"
		args.Delete = "Delete"
	}
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
	Message             string
	HasUpdate           bool
	Create              string
	Delete              string
	TargetCloudlet      string
	TargetCloudletParam string
	TargetCloudletArg   string
}

var tmplMessageTest = `
// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, modFuncs ...func(*edgeproto.{{.Message}})) {
	badPerm{{.Create}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
{{- if .HasUpdate}}
	badPermUpdate{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
{{- end}}
	badPerm{{.Delete}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}}, modFuncs...)
}

func badPermTestShow{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	list, status, err := testutil.TestPermShow{{.Message}}(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, showcount int, modFuncs ...func(*edgeproto.{{.Message}})) {
	goodPerm{{.Create}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- if .HasUpdate}}
	goodPermUpdate{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- end}}
	goodPerm{{.Delete}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})

	// make sure region check works
	_, status, err := testutil.TestPerm{{.Create}}{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
{{- if .HasUpdate}}
	_, status, err = testutil.TestPermUpdate{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
{{- end}}
	_, status, err = testutil.TestPerm{{.Delete}}{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}}, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	goodPermTestShow{{.Message}}(t, mcClient, uri, token, region, org, showcount)
}

func goodPermTestShow{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, count int) {
	list, status, err := testutil.TestPermShow{{.Message}}(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list))

	// make sure region check works
	list, status, err = testutil.TestPermShow{{.Message}}(mcClient, uri, token, "bad region", org)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token1, token2, region, org1, org2 string{{.TargetCloudletParam}}, showcount int, modFuncs ...func(*edgeproto.{{.Message}})) {
	badPermTest{{.Message}}(t, mcClient, uri, token1, region, org2{{.TargetCloudletArg}}, modFuncs...)
	badPermTestShow{{.Message}}(t, mcClient, uri, token1, region, org2)
	badPermTest{{.Message}}(t, mcClient, uri, token2, region, org1{{.TargetCloudletArg}}, modFuncs...)
	badPermTestShow{{.Message}}(t, mcClient, uri, token2, region, org1)

	goodPermTest{{.Message}}(t, mcClient, uri, token1, region, org1{{.TargetCloudletArg}}, showcount, modFuncs...)
	goodPermTest{{.Message}}(t, mcClient, uri, token2, region, org2{{.TargetCloudletArg}}, showcount, modFuncs...)
}
`

func (g *GenMC2) generateClientInterface(service *descriptor.ServiceDescriptorProto) {
	if !hasMc2Api(service) {
		return
	}
	g.P("type ", service.Name, "Client interface{")
	for _, method := range service.Method {
		if GetMc2Api(method) == "" {
			continue
		}
		in := gensupport.GetDesc(g.Generator, method.GetInputType())
		out := gensupport.GetDesc(g.Generator, method.GetOutputType())
		inname := *in.DescriptorProto.Name
		outname := *out.DescriptorProto.Name

		if gensupport.ServerStreaming(method) {
			// outstream
			g.P(method.Name, "(uri, token string, in *ormapi.Region", inname, ") ([]edgeproto.", outname, ", int, error)")
		} else {
			g.P(method.Name, "(uri, token string, in *ormapi.Region", inname, ") (*edgeproto.", outname, ", int, error)")
		}
	}
	g.P("}")
	g.P()
}

func (g *GenMC2) generateCtlGroup(service *descriptor.ServiceDescriptorProto) {
	if !hasMc2Api(service) {
		return
	}
	g.P("var ", service.Name, "Cmds = []*cli.Command{")
	for _, method := range service.Method {
		if GetMc2Api(method) == "" {
			continue
		}
		g.P(method.Name, "Cmd,")
	}
	g.P("}")
	g.P()
	serviceName := strings.TrimSuffix(*service.Name, "Api")
	groupName := getCliGroup(*service.Name)
	plural := "s"
	if strings.HasSuffix(serviceName, "s") {
		plural = ""
	}
	g.P("var ", service.Name, "CmdsGroup = cli.GenGroup(\"", groupName, "\", \"Manage ", serviceName, plural, "\", ", service.Name, "Cmds)")
	g.P()
	for ii, method := range service.Method {
		gensupport.GenerateMethodArgs(g.Generator, &g.support, method, true, ii)
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

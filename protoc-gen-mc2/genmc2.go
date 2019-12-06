package main

import (
	"sort"
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
	if !genFile(file) {
		return
	}

	g.P(gensupport.AutoGenComment)
	g.genapi = g.hasParam("genapi")
	g.gentest = g.hasParam("gentest")
	g.gentestutil = g.hasParam("gentestutil")
	g.genclient = g.hasParam("genclient")
	g.genctl = g.hasParam("genctl")
	g.gencliwrapper = g.hasParam("gencliwrapper")

	for _, service := range file.FileDescriptorProto.Service {
		g.generateService(service)
		if g.genclient {
			g.generateClientInterface(service)
		}
		if g.genctl {
			g.generateCtlGroup(service)
		}
		if g.gentestutil {
			if len(service.Method) == 0 {
				continue
			}
			g.generateRunApi(file.FileDescriptorProto, service)
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
	if g.gentest {
		for _, msg := range file.Messages() {
			if GetGenerateCud(msg.DescriptorProto) &&
				!GetGenerateShowTest(msg.DescriptorProto) {
				g.generateMessageTest(msg)
			}
		}
	}
}

func genFile(file *generator.FileDescriptor) bool {
	if len(file.FileDescriptorProto.Service) != 0 {
		for _, service := range file.FileDescriptorProto.Service {
			if len(service.Method) == 0 {
				continue
			}
			for _, method := range service.Method {
				if GetMc2Api(method) != "" {
					return true
				}
			}
		}
	}
	return false
}

func (g *GenMC2) generatePosts() {
	g.P("func addControllerApis(group *echo.Group) {")

	for _, file := range g.Generator.Request.ProtoFile {
		if !g.support.GenFile(*file.Name) {
			continue
		}
		if len(file.Service) == 0 {
			continue
		}
		for _, service := range file.Service {
			if len(service.Method) == 0 {
				continue
			}
			for _, method := range service.Method {
				if GetMc2Api(method) == "" {
					continue
				}
				g.P("group.POST(\"/ctrl/", method.Name,
					"\", ", method.Name, ")")
			}
		}
	}
	g.P("}")
	g.P()
}

func (g *GenMC2) generateService(service *descriptor.ServiceDescriptorProto) {
	if len(service.Method) == 0 {
		return
	}
	for _, method := range service.Method {
		g.generateMethod(*service.Name, method)
	}
}

func (g *GenMC2) generateMethod(service string, method *descriptor.MethodDescriptorProto) {
	api := GetMc2Api(method)
	if api == "" {
		return
	}
	apiVals := strings.Split(api, ",")
	if len(apiVals) != 3 {
		g.Fail("invalid mc2_api string, expected ResourceType,Action,OrgNameField")
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
	if args.Action == "ActionView" && strings.HasPrefix(args.MethodName, "Show") {
		args.Show = true
	}
	if !args.Outstream {
		args.ReturnErrArg = "nil, "
	}
	if !args.Show {
		args.TargetCloudlet = GetMc2TargetCloudlet(in.DescriptorProto)
		if args.TargetCloudlet != "" {
			args.TargetCloudletParam = ", targetCloudlet *edgeproto.CloudletKey"
			args.TargetCloudletArg = ", targetCloudlet"
		}
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
		g.importOrmapi = true
		g.importStrings = true
		g.importCli = true
		if strings.HasPrefix(*method.Name, "Update"+args.InName) && gensupport.HasGrpcFields(in.DescriptorProto) {
			args.SetFields = true
		}
	} else if g.gencliwrapper {
		tmpl = g.tmplMethodCliWrapper
		args.NoConfig = gensupport.GetNoConfig(in.DescriptorProto, method)
		g.importOrmapi = true
		g.importStrings = true
	} else {
		tmpl = g.tmpl
		g.importEcho = true
		g.importHttp = true
		g.importContext = true
		g.importOrmapi = true
		g.importGrpcStatus = true
		if args.OrgValid {
			g.importLog = true
		}
		if args.Outstream {
			g.importIO = true
			g.importJson = true
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
}

var tmplApi = `
{{- if .GenStruct}}
type Region{{.InName}} struct {
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
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	rc.region = in.Region
{{- if .OrgValid}}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", in.{{.InName}}.{{.OrgField}})
{{- end}}
{{- if .Outstream}}
	// stream func may return "forbidden", so don't write
	// header until we know it's ok
	wroteHeader := false
	err = {{.MethodName}}Stream(ctx, rc, &in.{{.InName}}, func(res *edgeproto.{{.OutName}}) {
		if !wroteHeader {
			c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c.Response().WriteHeader(http.StatusOK)
			wroteHeader = true
		}
		payload := ormapi.StreamPayload{}
		payload.Data = res
		json.NewEncoder(c.Response()).Encode(payload)
		c.Response().Flush()
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		if !wroteHeader {
			return setReply(c, err, nil)
		}
		res := ormapi.Result{}
		res.Message = err.Error()
		res.Code = http.StatusBadRequest
		payload := ormapi.StreamPayload{Result: &res}
		json.NewEncoder(c.Response()).Encode(payload)
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
	Ok(obj *edgeproto.{{.InName}}) bool
}
{{- end}}

{{if .Outstream}}
func {{.MethodName}}Stream(ctx context.Context, rc *RegionContext, obj *edgeproto.{{.InName}}, cb func(res *edgeproto.{{.OutName}})) error {
{{- else}}
func {{.MethodName}}Obj(ctx context.Context, rc *RegionContext, obj *edgeproto.{{.InName}}) (*edgeproto.{{.OutName}}, error) {
{{- end}}
{{- if (not .SkipEnforce)}}
{{- if and .Show .CustomAuthz}}
	var authz {{.MethodName}}Authz
	var err error
	if !rc.skipAuthz {
		authz, err = new{{.MethodName}}Authz(ctx, rc.region, rc.username, {{.Resource}}, {{.Action}})
		if err == echo.ErrForbidden {
			return {{.ReturnErrArg}}nil
		}
		if err != nil {
			return {{.ReturnErrArg}}err
		}
	}
{{- else if and .Show (not .CustomAuthz)}}
	var authz *ShowAuthz
	var err error
	if !rc.skipAuthz {
		authz, err = NewShowAuthz(ctx, rc.region, rc.username, {{.Resource}}, {{.Action}})
		if err == echo.ErrForbidden {
			return {{.ReturnErrArg}}nil
		}
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
	if !rc.skipAuthz && !authorized(ctx, rc.username, {{.Org}},
		{{.Resource}}, {{.Action}}) {
		return {{.ReturnErrArg}}echo.ErrForbidden
	}
{{- end}}
{{- end}}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
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
			if !authz.Ok(res) {
				continue
			}
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
func Test{{.MethodName}}(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.{{.InName}}) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func Test{{.MethodName}}(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.{{.InName}}) (edgeproto.{{.OutName}}, int, error) {
{{- end}}
	dat := &ormapi.Region{{.InName}}{}
	dat.Region = region
	dat.{{.InName}} = *in
	return mcClient.{{.MethodName}}(uri, token, dat)
}

{{- if .Outstream}}
func TestPerm{{.MethodName}}(mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}) ([]edgeproto.{{.OutName}}, int, error) {
{{- else}}
func TestPerm{{.MethodName}}(mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}) (edgeproto.{{.OutName}}, int, error) {
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
	return Test{{.MethodName}}(mcClient, uri, token, region, in)
}
`

var tmplMethodTest = `

var _ = edgeproto.GetFields

func badPerm{{.MethodName}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}})
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPerm{{.MethodName}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}) {
	_, status, err := testutil.TestPerm{{.MethodName}}(mcClient, uri, token, region, org{{.TargetCloudletArg}})
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
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) (edgeproto.{{.OutName}}, int, error) {
	out := edgeproto.{{.OutName}}{}
	status, err := s.PostJson(uri+"/auth/ctrl/{{.MethodName}}", token, in, &out)
	return out, status, err
}
{{- end}}
`

var tmplMethodCtl = `
var {{.MethodName}}Cmd = &cli.Command{
	Use: "{{.MethodName}}",
{{- if .Show}}
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append({{.InName}}RequiredArgs, {{.InName}}OptionalArgs...), " "),
{{- else if .HasMethodArgs}}
	RequiredArgs: strings.Join(append([]string{"region"}, {{.MethodName}}RequiredArgs...), " "),
	OptionalArgs: strings.Join({{.MethodName}}OptionalArgs, " "),
{{- else}}
	RequiredArgs: strings.Join(append([]string{"region"}, {{.InName}}RequiredArgs...), " "),
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
	objmap["fields"] = cli.GetSpecifiedFields(objmap, &edgeproto.{{.InName}}{}, cli.JsonNamespace)
}
{{- end}}

`

var tmplMethodCliWrapper = `
{{- if .Outstream}}
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) ([]edgeproto.{{.OutName}}, int, error) {
	args := []string{"region", "{{.MethodName}}"}
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
func (s *Client) {{.MethodName}}(uri, token string, in *ormapi.Region{{.InName}}) (edgeproto.{{.OutName}}, int, error) {
	args := []string{"region", "{{.MethodName}}"}
	out := edgeproto.{{.OutName}}{}
	noconfig := strings.Split("{{.NoConfig}}", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	return out, st, err
}
{{- end}}

`

func (g *GenMC2) generateMessageTest(desc *generator.Descriptor) {
	message := desc.DescriptorProto
	args := msgArgs{
		Message:        *message.Name,
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
	allowedActions := []string{
		"Create",
		"Update",
		"Delete",
	}
	out := make(map[string]map[string]string)
	for _, method := range service.Method {
		found := false
		action := ""
		for _, act := range allowedActions {
			if strings.HasPrefix(*method.Name, act) {
				found = true
				action = act
				break
			}
		}
		if !found {
			continue
		}
		cmd := strings.TrimPrefix(*method.Name, action)
		if _, ok := out[cmd]; ok {
			out[cmd][action] = *method.Name
		} else {
			out[cmd] = map[string]string{
				action: *method.Name,
			}
		}
	}
	for k, v := range out {
		readMap := false
		if _, ok := v["Update"]; ok {
			readMap = true
		}
		objStr := strings.ToLower(string(k[0])) + string(k[1:len(k)])
		g.P()
		g.P("func RunMc", k, "Api(mcClient ormclient.Api, uri, token, region string, data *[]edgeproto.", k, ", dataIn interface{}, rc *bool, mode string) {")
		if readMap {
			g.importOS = true
			g.P("var dataInList []interface{}")
			g.P("var ok bool")
			g.P("if dataIn != nil {")
			g.P("dataInList, ok = dataIn.([]interface{})")
			g.P("if !ok {")
			g.P("fmt.Fprintf(os.Stderr, \"invalid data in ", objStr, ": %v\\n\", dataIn)")
			g.P("os.Exit(1)")
			g.P("}")
			g.P("}")
		}
		if readMap {
			g.P("for ii, ", objStr, " := range *data {")
			g.P("dataMap, ok := dataInList[ii].(map[string]interface{})")
			g.P("if !ok {")
			g.P("fmt.Fprintf(os.Stderr, \"invalid data in ", objStr, ": %v\\n\", dataInList[ii])")
			g.P("os.Exit(1)")
			g.P("}")
		} else {
			g.P("for _, ", objStr, " := range *data {")
		}
		g.P("in := &ormapi.Region", k, "{")
		g.P("Region: region,")
		g.P(k, ": ", objStr, ",")
		g.P("}")

		mapKeys := []string{}
		for mapKey, _ := range v {
			mapKeys = append(mapKeys, mapKey)
		}
		sort.Strings(mapKeys)
		g.P("switch mode {")
		for _, action := range mapKeys {
			fName := v[action]
			g.P("case \"", strings.ToLower(action), "\":")
			if action == "Update" {
				g.importCli = true
				g.P("in.", k, ".Fields = cli.GetSpecifiedFields(dataMap, &in.", k, ", cli.YamlNamespace)")
			}
			g.P("_, st, err := mcClient.", fName, "(uri, token, in)")
			g.P("checkMcErr(\"", fName, "\", st, err, rc)")
		}
		g.P("default:")
		g.P("return")
		g.P("}")
		g.P("}")
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
func badPermTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}) {
	badPerm{{.Create}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- if .HasUpdate}}
	badPermUpdate{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- end}}
	badPerm{{.Delete}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
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
func goodPermTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string{{.TargetCloudletParam}}, showcount int) {
	goodPerm{{.Create}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- if .HasUpdate}}
	goodPermUpdate{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})
{{- end}}
	goodPerm{{.Delete}}{{.Message}}(t, mcClient, uri, token, region, org{{.TargetCloudletArg}})

	// make sure region check works
	_, status, err := testutil.TestPerm{{.Create}}{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
{{- if .HasUpdate}}
	_, status, err = testutil.TestPermUpdate{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
{{- end}}
	_, status, err = testutil.TestPerm{{.Delete}}{{.Message}}(mcClient, uri, token, "bad region", org{{.TargetCloudletArg}})
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
func permTest{{.Message}}(t *testing.T, mcClient *ormclient.Client, uri, token1, token2, region, org1, org2 string{{.TargetCloudletParam}}, showcount int) {
	badPermTest{{.Message}}(t, mcClient, uri, token1, region, org2{{.TargetCloudletArg}})
	badPermTestShow{{.Message}}(t, mcClient, uri, token1, region, org2)
	badPermTest{{.Message}}(t, mcClient, uri, token2, region, org1{{.TargetCloudletArg}})
	badPermTestShow{{.Message}}(t, mcClient, uri, token2, region, org1)

	goodPermTest{{.Message}}(t, mcClient, uri, token1, region, org1{{.TargetCloudletArg}}, showcount)
	goodPermTest{{.Message}}(t, mcClient, uri, token2, region, org2{{.TargetCloudletArg}}, showcount)
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
			g.P(method.Name, "(uri, token string, in *ormapi.Region", inname, ") (edgeproto.", outname, ", int, error)")
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
	for ii, method := range service.Method {
		gensupport.GenerateMethodArgs(g.Generator, &g.support, method, true, ii)
	}
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

func GetMc2CustomAuthz(method *descriptor.MethodDescriptorProto) bool {
	return proto.GetBoolExtension(method.Options, protogen.E_Mc2CustomAuthz, false)
}

func GetMc2TargetCloudlet(message *descriptor.DescriptorProto) string {
	return gensupport.GetStringExtension(message.Options, protogen.E_Mc2TargetCloudlet, "")
}

func GetGenerateCud(message *descriptor.DescriptorProto) bool {
	return proto.GetBoolExtension(message.Options, protogen.E_GenerateCud, false)
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

package main

import (
	"text/template"

	"github.com/edgexr/edge-cloud-platform/pkg/gensupport"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
	"github.com/gogo/protobuf/protoc-gen-gogo/generator"
)

type RedisAPIGen struct {
	*generator.Generator
	support gensupport.PluginSupport
	apiTmpl *template.Template
}

func (s *RedisAPIGen) Name() string {
	return "RedisAPIGen"
}

func (s *RedisAPIGen) Init(g *generator.Generator) {
	s.Generator = g
	s.support.Init(g.Request)
	s.apiTmpl = template.Must(template.New("api").Parse(apiTemplate))
}

func (s *RedisAPIGen) GenerateImports(file *generator.FileDescriptor) {
	// imports, if any
	s.support.PrintUsedImports(s.Generator)
	s.PrintImport("", "context")
	s.PrintImport("", "github.com/go-redis/redis/v8")
}

func (s *RedisAPIGen) Generate(file *generator.FileDescriptor) {
	s.support.InitFile()
	if !s.support.GenFile(*file.FileDescriptorProto.Name) {
		return
	}

	if len(file.FileDescriptorProto.Service) != 0 {
		for _, service := range file.FileDescriptorProto.Service {
			s.generateService(file, service)
		}
	}
	if s.Generator.Buffer.Len() != 0 {
		s.P(gensupport.AutoGenComment)
		gensupport.RunParseCheck(s.Generator, file)
	}
}

func (s *RedisAPIGen) generateService(file *generator.FileDescriptor, service *descriptor.ServiceDescriptorProto) {
	if len(service.Method) == 0 {
		return
	}
	if !gensupport.GetRedisApi(service) {
		return
	}
	sargs := &serviceArgs{
		Service: *service.Name,
	}
	for _, method := range service.Method {
		in := gensupport.GetDesc(s.Generator, method.GetInputType())
		out := gensupport.GetDesc(s.Generator, method.GetOutputType())
		if method.ClientStreaming != nil && *method.ClientStreaming {
			s.Fail("Internal API client streaming not supported ", *service.Name, *method.Name)
		}
		margs := methodArgs{
			Method: *method.Name,
			In:     s.support.FQTypeName(s.Generator, in),
			Out:    s.support.FQTypeName(s.Generator, out),
		}
		if method.ServerStreaming != nil && *method.ServerStreaming {
			margs.StreamOut = true
		}
		sargs.Methods = append(sargs.Methods, margs)
	}
	err := s.apiTmpl.Execute(s, sargs)
	if err != nil {
		s.Fail("Failed to execute api template for ", *service.Name, ": ", err.Error(), "\n")
	}
}

type serviceArgs struct {
	Service string
	Methods []methodArgs
}

type methodArgs struct {
	Method    string
	In        string
	Out       string
	StreamOut bool
}

var apiTemplate = `
type {{.Service}}Server interface {
{{- range .Methods }}
{{- if .StreamOut }}
	{{.Method}}(ctx context.Context, in *{{.In}}, send func(*{{.Out}}) error) error
{{- else }}
	{{.Method}}(ctx context.Context, in *{{.In}}) (*{{.Out}}, error)
{{- end }}
{{- end }}
}

type {{.Service}}Client interface {
{{- range .Methods }}
{{- if .StreamOut }}
	{{.Method}}(ctx context.Context, in *{{.In}}, recv func(*{{.Out}}) error) error
{{- else }}
	{{.Method}}(ctx context.Context, in *{{.In}}) (*{{.Out}}, error)
{{- end }}
{{- end }}
}

type {{.Service}}ClientHandler struct {
	api *UnaryAPI
	serviceType string
}

func Get{{.Service}}Client(client *redis.Client, serviceType string) {{.Service}}Client {
	handler := &{{.Service}}ClientHandler{
		api: NewUnaryAPI(client),
		serviceType: serviceType,
	}
	return handler
}

{{range .Methods }}
{{- if .StreamOut }}
func (s *{{$.Service}}ClientHandler) {{.Method}}(ctx context.Context, in *{{.In}}, recv func(*{{.Out}}) error) error {
	methodName := s.serviceType +"/{{$.Service}}/{{.Method}}"
	replyBuf := &{{.Out}}{}
	cb := func() error {
		return recv(replyBuf)
	}
	return s.api.DoStreamRequest(ctx, methodName, in, replyBuf, cb)
}
{{- else }}
func (s *{{$.Service}}ClientHandler) {{.Method}}(ctx context.Context, in *{{.In}}) (*{{.Out}}, error) {
	methodName := s.serviceType +"/{{$.Service}}/{{.Method}}"
	replyBuf := &{{.Out}}{}
	err := s.api.DoRequest(ctx, methodName, in, replyBuf)
	return replyBuf, err
}

{{end }}
{{- end }}

type {{.Service}}ServerHandler struct {
	api *UnaryAPI
	serviceType string
	server {{.Service}}Server
}

func Get{{.Service}}Server(client *redis.Client, serviceType string, server {{.Service}}Server) *{{.Service}}ServerHandler {
	handler := &{{.Service}}ServerHandler{
		api: NewUnaryAPI(client),
		serviceType: serviceType,
		server: server,
	}
	return handler
}

// Start the server, use context cancel to stop.
func (s *{{.Service}}ServerHandler) Start(ctx context.Context) {
{{- range .Methods }}
	// {{$.Service}} {{.Method}}
	{{.Method}} := s.serviceType +"/{{$.Service}}/{{.Method}}"
	get{{.Method}}ReqBuf := func() interface{} {
		return &{{.In}}{}
	}
{{- if .StreamOut }}
	{{.Method}}Handler := func(ctx context.Context, req interface{}, sendReply StreamReplyCb) error {
		in, _ := req.(*{{.In}})
		cb := func(reply *{{.Out}}) error {
			return sendReply(reply)
		}
		return s.server.{{.Method}}(ctx, in, cb)
	}
	go s.api.HandleStreamRequests(ctx, {{.Method}}, get{{.Method}}ReqBuf, {{.Method}}Handler)

{{- else }}
	{{.Method}}Handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		in, _ := req.(*{{.In}})
		return s.server.{{.Method}}(ctx, in)
	}
	go s.api.HandleRequests(ctx, {{.Method}}, get{{.Method}}ReqBuf, {{.Method}}Handler)
{{end }}

{{- end }}	
}

`

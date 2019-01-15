package server

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/julienschmidt/httprouter"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/k8sopenstack"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

//Agent service handlers.

//Server for GRPC
type Server struct{}

var proxyMap = make(map[string]string)

var supportProvisioning = false

func init() {
	if supportProvisioning {
		k8sopenstack.Initialize()
	}
}

//Provision a kubernetes cluster on openstack for the given Tenant
func (srv *Server) Provision(ctx context.Context, req *api.ProvisionRequest) (res *api.ProvisionResponse, err error) {
	log.Debugln("req", req)
	if len(req.Provisions) < 1 {
		return nil, fmt.Errorf("missing provisions")
	}
	if err := k8sopenstack.CreateKubernetesCluster(req.Provisions[0]); err != nil { ///XXX only one for now
		return nil, fmt.Errorf("can't create kubernetes cluster on openstack, %v", err)
	}

	res = &api.ProvisionResponse{
		Message: req.Message,
		Status:  "OK",
	}

	return res, nil
}

//Destroy a kubernetes cluster on openstack for the given Tenant
func (srv *Server) Destroy(ctx context.Context, req *api.ProvisionRequest) (res *api.ProvisionResponse, err error) {
	log.Debugln("req", req)
	if len(req.Provisions) < 1 {
		return nil, fmt.Errorf("missing provisions")
	}
	if err := k8sopenstack.DeleteKubernetesCluster(req.Provisions[0]); err != nil { ///XXX only one for now
		return nil, fmt.Errorf("can't create kubernetes cluster on openstack, %v", err)
	}

	res = &api.ProvisionResponse{
		Message: req.Message,
		Status:  "ok",
	}

	return res, nil
}

//Provision and Destroy are deprecated for now until the TLS works with GDDT and other providers properly.
// They work on custom Openstack cluster created on bare-metal, such as Packet.net.  Unfortunately they don't work with GDDT.
// Instead, use the `oscli` method.  Move the provisioning further out and do it remotely, not as part of the agent.

//Proxy traffic betwwen kubernetes pods, via openstack subnet/network, iptables, and external network
func (srv *Server) Proxy(ctx context.Context, req *api.ProxyRequest) (res *api.ProxyResponse, err error) {
	log.Debugln("req", req)
	if req.Message == "add" {
		if len(req.Proxies) < 1 {
			res = &api.ProxyResponse{Message: fmt.Sprintf("Error, missing proxies"), Status: "Error"}
			return res, fmt.Errorf("missing proxy definitions")
		}
		var aerr error
		//TODO layer 4 proxy
		for _, p := range req.Proxies {
			aerr = addOrigin(p.Path, p.Origin)
			if aerr != nil {
				break
			}
		}
		if aerr != nil {
			res = &api.ProxyResponse{Message: fmt.Sprintf("Error, cannot add proxy"), Status: "Error"}
			return res, aerr
		}
	} else if req.Message == "list" {
		res = &api.ProxyResponse{Message: req.Message, Status: fmt.Sprintf("%v", proxyMap)}
		return res, nil
	} else if req.Message == "delete" {
		if len(req.Proxies) < 1 {
			res = &api.ProxyResponse{Message: fmt.Sprintf("Error, missing proxies"), Status: "Error"}
			return res, fmt.Errorf("missing proxy definitions")
		}
		var berr error
		for _, p := range req.Proxies {
			berr = delOrigin(p.Path, p.Origin)
			if berr != nil {
				break
			}
		}
		if berr != nil {
			res = &api.ProxyResponse{Message: fmt.Sprintf("Error, cannot delete proxy"), Status: "Error"}
			return res, fmt.Errorf("can't delete proxy")
		}
	} else {
		//TODO
		res = &api.ProxyResponse{Message: fmt.Sprintf("Error, invalid request %s", req.Message), Status: "Error"}
		return res, fmt.Errorf("invalid request")
	}
	res = &api.ProxyResponse{Message: req.Message, Status: "OK"}
	return res, nil
}

var router *httprouter.Router

func addOrigin(path, origin string) error {
	log.Debugf("addOrigin path %s origin %s", path, origin)
	val, ok := proxyMap[path]
	if ok {
		log.Debugln("already exists, will replace", path, val, origin)
		//return fmt.Errorf("Path %s exists for %s", path, val)
	}
	originURL, err := url.Parse(origin)
	reverseProxy := httputil.NewSingleHostReverseProxy(originURL)
	if err != nil {
		log.Debugln("can't parse origin", origin, err)
		return fmt.Errorf("Cannot parse origin %s,%v", origin, err)
	}
	if router == nil {
		log.Debugln("no router")
		return fmt.Errorf("No router")
	}
	reverseProxy.Director = func(req *http.Request) {
		log.Debugln("director", req)
		val, ok := proxyMap[path]
		if !ok {
			log.Debugln("no proxy path for", path)
			return
		}
		if val != "" {
			if strings.HasPrefix(val, "DELETED-") {
				log.Debugln("proxy path deleted", val)
				return
			}
		}
		// TODO make proxmap[] -> struct { algo, []paths} for load-balancing
		//   distance, latency based routing
		//   additional header injection for bearer token
		//   short-circuit for misbehaving services, requires monitoring
		//   gather stats for metering, performance measurement
		//   caching static content
		//   dynamic service discovery
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", originURL.Host)
		req.URL.Scheme = originURL.Scheme
		req.URL.Host = originURL.Host
		wildcardIndex := strings.Index(path, "*")
		proxyPath := singleJoiningSlash(originURL.Path, req.URL.Path[wildcardIndex:])
		if strings.HasSuffix(proxyPath, "/") && len(proxyPath) > 1 {
			proxyPath = proxyPath[:len(proxyPath)-1]
		}
		log.Debugln("req", req, "origin", originURL, req.URL.Path, "=>", proxyPath)
		req.URL.Path = proxyPath
	}
	if !ok {
		// router panics if we add handlers again, reuse handlers for the same paths.
		router.Handle("GET", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
			reverseProxy.ServeHTTP(w, r)
		})
		router.Handle("POST", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
			reverseProxy.ServeHTTP(w, r)
		})
	}
	proxyMap[path] = origin //TODO: store in database
	return nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func delOrigin(path, origin string) error {
	log.Debugln("delete proxy", path, origin)
	//delete(proxyMap, path)
	// if router == nil {
	// 	log.Debugln("no router")
	// 	return fmt.Errorf("No router")
	// }
	// router.Handle("GET", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// 	http.Error(w, "missing key", http.StatusNotFound)
	// })
	// router.Handle("POST", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// 	http.Error(w, "missing key", http.StatusNotFound)
	// })
	//replace not delete
	proxyMap[path] = "DELETED-" + origin
	return nil
}

//Status returns status information of the kubernetes cluster on openstack for a given tenant
func (srv *Server) Status(ctx context.Context, req *api.StatusRequest) (res *api.StatusResponse, err error) {
	res = &api.StatusResponse{
		Message: "OK",
	}

	return res, nil
}

//Route directs requests to paths to be serviced
func (srv *Server) Route(ctx context.Context, req *api.RouteRequest) (res *api.RouteResponse, err error) {
	if req.Message == "add" {
		if len(req.Routes) < 1 {
			return nil, fmt.Errorf("missing Route definitions")
		}
		for _, r := range req.Routes {
			err = addRoute(r.Subnet, r.Gateway, r.Dev)
			if err != nil {
				res = &api.RouteResponse{
					Message: fmt.Sprintf("Error, cannot add Route %s %s %s, %v", r.Subnet, r.Gateway, r.Dev, err),
				}
				return res, err
			}
		}
		res = &api.RouteResponse{
			Message: req.Message,
			Status:  "OK",
		}
		return res, nil
	} else if req.Message == "list" {
		rl, rerr := listRoutes()
		if rerr != nil {
			res = &api.RouteResponse{
				Message: req.Message,
				Status:  fmt.Sprintf("can't list route, %v", rerr),
			}
			return res, rerr
		}
		res = &api.RouteResponse{
			Message: req.Message,
			Status:  fmt.Sprintf("%v", rl),
		}
		return res, nil
	} else if req.Message == "delete" {
		if len(req.Routes) < 1 {
			return nil, fmt.Errorf("missing Route definitions")
		}
		for _, r := range req.Routes {
			err = delRoute(r.Subnet, r.Gateway, r.Dev)
			if err != nil {
				res = &api.RouteResponse{
					Message: fmt.Sprintf("Error, cannot del Route %s %s %s, %v", r.Subnet, r.Gateway, r.Dev, err),
				}
				return res, err
			}
		}
		res = &api.RouteResponse{
			Message: req.Message,
			Status:  "OK",
		}
		return res, nil
	} else {
		//TODO
		res = &api.RouteResponse{
			Message: fmt.Sprintf("Error, invalid request %s", req.Message),
		}
		return res, nil
	}
}

func addRoute(subnet, gateway, dev string) error {
	log.Debugf("addRoute subnet %s gateway %s dev %s", subnet, gateway, dev)

	out, err := sh.Command("ip", "route", "add", subnet, "via", gateway, "dev", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("can't add route %s %s %s, %s, %v", subnet, gateway, dev, out, err)
	}
	return nil
}
func delRoute(subnet, gateway, dev string) error {
	log.Debugf("delRoute subnet %s gateway %s dev %s", subnet, gateway, dev)

	out, err := sh.Command("ip", "route", "del", subnet, "via", gateway, "dev", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("can't delete route %s %s %s, %s, %v", subnet, gateway, dev, out, err)
	}
	return nil
}

func listRoutes() (string, error) {
	log.Debugf("list routes")

	out, err := sh.Command("ip", "route", "show").Output()
	if err != nil {
		return "", fmt.Errorf("can't list route, %v", err)
	}
	return string(out), err
}

func GetNewRouter() *httprouter.Router {
	log.Debugln("get new router")
	router = httprouter.New()
	return router
}

//TODO add tcpproxy. instantiate docker tcpproxy for port pairs as requested for L4 rev proxy

func (srv *Server) Nginx(ctx context.Context, req *api.NginxRequest) (res *api.NginxResponse, err error) {
	log.Debugln("Received Nginx request", "name", req.Name, "network", req.Network, "ports", req.Ports)
	if req.Message == "add" {
		if len(req.Ports) < 1 {
			res = &api.NginxResponse{Message: fmt.Sprintf("Error, missing ports"), Status: "Error"}
			return res, fmt.Errorf("missing ports definitions")
		}
		aerr := CreateNginx(req.Name, req.Network, req.Ports)
		if aerr != nil {
			res = &api.NginxResponse{Message: fmt.Sprintf("Error, cannot create Nginx, name %s, ports %v", req.Name, req.Ports), Status: "Error"}
			return res, aerr
		}
	} else if req.Message == "list" {
		names, err := ListNginx()
		if err != nil {
			res = &api.NginxResponse{Message: fmt.Sprintf("cannot get list of nginx instances, %v", err), Status: "Error"}
			return res, err
		}
		res = &api.NginxResponse{Message: req.Message, Status: fmt.Sprintf("%v", names)}
		return res, nil
	} else if req.Message == "delete" {
		berr := DeleteNginx(req.Name)
		if berr != nil {
			res = &api.NginxResponse{Message: fmt.Sprintf("Error, cannot delete Nginx, name %s, ports %v", req.Name, req.Ports), Status: "Error"}
			return res, berr
		}
	} else {
		//TODO
		res = &api.NginxResponse{Message: fmt.Sprintf("Error, invalid request %s", req.Message), Status: "Error"}
		return res, fmt.Errorf("invalid request")
	}

	res = &api.NginxResponse{
		Message: "OK",
	}
	return res, nil
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CreateNginx creates an nginx container with the specified name and optional network
// with the specified ports
func CreateNginx(name string, network string, ports []*api.NginxPort) error {
	log.Debugln("create nginx", name, ports)
	pwd, err := os.Getwd()
	if err != nil {
		log.Debugln("can't get cwd", err)
		return err
	}
	dir := pwd + "/nginx/" + name
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Debugln("can't create dir", dir, err)
		return err
	}

	// certs are needed only for L7, for which we have a path
	useTLS := false
	for _, p := range ports {
		if p.Path != "" {
			useTLS = true
		}
	}
	if useTLS {
		if !fileExists(pwd + "/cert.pem") {
			log.Debugln("cert.pem does not exist")
			return fmt.Errorf("while creating nginx %s, cert.pem does not exist", name)
		}
		if !fileExists(pwd + "/key.pem") {
			log.Debugln("key.pem does not exist")
			return fmt.Errorf("while creating nginx %s, key.pem does not exist", name)
		}
	}

	errlogFile := dir + "/err.log"
	f, err := os.Create(errlogFile)
	if err != nil {
		log.Debugln("while creating nginx proxy can't create err.log", name)
		return err
	}
	f.Close()
	nconfName := dir + "/nginx.conf"
	_, err = createNginxConf(nconfName, name, ports)
	if err != nil {
		log.Debugln("while creating nginx proxy can't create conf", name)
		return err
	}
	log.Debugln("create nginx conf", nconfName)
	defaultConf := dir + "/default.conf"
	_, err = createNginxDefaultConf(defaultConf, name, ports)
	if err != nil {
		log.Debugln("while creating nginx proxy, can't create default conf", name)
		return err
	}

	cmdArgs := []string{"run", "-d", "--rm", "--name", name}
	if network == "" {
		// when runnning in DIND it cannot use host mode and so must expose the ports
		cmdArgs = append(cmdArgs, "--network", network)
		for _, p := range ports {
			pstr := fmt.Sprintf("%s:%s", p.External, p.External)
			cmdArgs = append(cmdArgs, "-p", pstr)
		}
	} else {
		cmdArgs = append(cmdArgs, "--net=host")
	}
	cmdArgs = append(cmdArgs, []string{"-v", defaultConf + ":/etc/nginx/conf.d/default.conf", "-v", dir + ":/var/www/.cache", "-v", "/etc/ssl/certs:/etc/ssl/certs", "-v", pwd + "/cert.pem:/etc/ssl/certs/server.crt", "-v", pwd + "/key.pem:/etc/ssl/certs/server.key", "-v", errlogFile + ":/var/log/nginx/error.log", "-v", nconfName + ":/etc/nginx/nginx.conf", "nginx"}...)
	fmt.Printf("Nginx command args %+v\n", cmdArgs)
	out, err := sh.Command("docker", cmdArgs).CombinedOutput()

	if err != nil {
		return fmt.Errorf("can't create nginx container %s, %s, %v", name, out, err)
	}
	log.Debugln("created nginx container", name)
	return nil
}

var nginxConfTmpl = `
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

{{if .L7 -}}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    keepalive_timeout  65;
    include /etc/nginx/conf.d/*.conf;
    {{- range .HTTPSpec}}
    server {
 	listen {{.Port}} ssl;
	ssl_certificate        /etc/ssl/certs/server.crt;
	ssl_certificate_key    /etc/ssl/certs/server.key;
	location {{.Path}} {
		proxy_pass http://{{.Origin}};
	}
    }
    {{- end}}
}
{{- end}}

{{if .L4 -}}
stream {
	{{- range .TCPSpec}}
	server {
		listen {{.Port}};
		proxy_pass {{.Origin}};
	}
	{{- end}}
	{{- range .UDPSpec}}
	server {
		listen {{.Port}} udp;
		proxy_pass {{.Origin}};
	}
	{{- end}}
}
{{- end}}
`

type ProxySpec struct {
	Name     string
	Instance string
	L4, L7   bool
	HTTPSpec []*HTTPSpecDetail
	UDPSpec  []*UDPSpecDetail
	TCPSpec  []*TCPSpecDetail
}

type HTTPSpecDetail struct {
	Port   string
	Path   string
	Origin string
}

type TCPSpecDetail struct {
	Port   string
	Origin string
}

type UDPSpecDetail struct {
	Port   string
	Origin string
}

func createNginxConf(confname, name string, ports []*api.NginxPort) (*string, error) {
	log.Debugln("create nginx conf", confname, name, ports)
	ps, err := createNginxProxySpec(name, ports)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("nginxconf").Parse(nginxConfTmpl)
	if err != nil {
		return nil, err
	}
	var outbuffer bytes.Buffer
	err = tmpl.Execute(&outbuffer, ps)
	if err != nil {
		return nil, err
	}
	confbytes := outbuffer.Bytes()
	err = writeFile(confname, confbytes)
	if err != nil {
		return nil, err
	}
	confstr := string(confbytes)
	return &confstr, nil
}

var nginxDefaultConfTmpl = `
server {
    listen       {{.Port}};
    server_name  {{.Name}};
    ssl_certificate        /etc/ssl/certs/server.crt;
    ssl_certificate_key    /etc/ssl/certs/server.key;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
}
`

type DefaultConf struct {
	Name, Port string
}

func createNginxDefaultConf(confname, name string, ports []*api.NginxPort) (*string, error) {
	log.Debugln("create nginx default conf", confname, name, ports)
	port := GetNginxDefaultPort()
	if port == "" {
		return nil, fmt.Errorf("cannot reserve nginx http port")
	}
	dc := &DefaultConf{Port: port, Name: name}
	tmpl, err := template.New("defaultnginxconf").Parse(nginxDefaultConfTmpl)
	if err != nil {
		return nil, err
	}
	var outbuffer bytes.Buffer
	err = tmpl.Execute(&outbuffer, dc)
	if err != nil {
		return nil, err
	}
	confbytes := outbuffer.Bytes()
	err = writeFile(confname, confbytes)
	if err != nil {
		return nil, err
	}
	confstr := string(confbytes)
	return &confstr, nil
}

var nginxDefaultPortStart = 64333 //XXX
var nginxDefaultPortMax = 64933   //XXX

func GetNginxDefaultPort() string {
	timeout := time.Second
	for i := nginxDefaultPortStart; i < nginxDefaultPortMax; i++ {
		port := fmt.Sprintf("%d", i)
		conn, err := net.DialTimeout("tcp", ":"+port, timeout)
		if conn != nil {
			conn.Close()
			log.Debugln("being used", port)
			continue
		}
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				log.Debugln("using nginx http port", port)
				return port
			}
			log.Debugln("unexpect dial error", err)
		}
	}
	log.Debugln("no ports available in range", nginxDefaultPortStart, nginxDefaultPortMax)
	return ""
}

func createNginxProxySpec(name string, ports []*api.NginxPort) (*ProxySpec, error) {
	ps := &ProxySpec{Name: name}
	for _, p := range ports {
		switch p.Mexproto {
		case "LProtoHTTP":
			ps.L7 = true
			hsd := &HTTPSpecDetail{Port: p.External, Path: p.Path, Origin: p.Origin}
			ps.HTTPSpec = append(ps.HTTPSpec, hsd)
		case "LProtoTCP":
			ps.L4 = true
			tsd := &TCPSpecDetail{Port: p.External, Origin: p.Origin}
			ps.TCPSpec = append(ps.TCPSpec, tsd)
		case "LProtoUDP":
			ps.L4 = true
			usd := &UDPSpecDetail{Port: p.External, Origin: p.Origin}
			ps.UDPSpec = append(ps.UDPSpec, usd)
		default:
			return nil, fmt.Errorf("cannot create nginx conf, invalid  mexproto %s", p.Mexproto)
		}
	}
	return ps, nil
}

func writeFile(confname string, confbytes []byte) error {
	f, err := os.Create(confname)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(confbytes)
	if err != nil {
		return err
	}
	return nil
}

func DeleteNginx(name string) error {
	out, err := sh.Command("docker", "kill", name).Output()
	if err != nil {
		return fmt.Errorf("can't kill nginx container %s, %s, %v", name, out, err)
	}
	log.Debugln("deleted nginx container", name)
	return nil
}

func ListNginx() ([]string, error) {
	out, err := sh.Command("docker", "ps", "--format", "'{{.Names}}'").Output()
	if err != nil {
		return nil, fmt.Errorf("can't list nginx container %s, %v", out, err)
	}
	outstr := string(out)
	log.Debugln("list of nginx containers", outstr)
	names := strings.Split(outstr, "\n")
	return names, nil
}

package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/codeskyblue/go-sh"
	"github.com/julienschmidt/httprouter"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/k8sopenstack"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
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
		return res, err
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
	if val, ok := proxyMap[path]; ok {
		log.Debugln("already exists", path)
		return fmt.Errorf("Path %s exists for %s", path, val)
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
		if _, ok := proxyMap[path]; !ok {
			return //XXX no way to really delete route
		}
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", originURL.Host)
		req.URL.Scheme = originURL.Scheme
		req.URL.Host = originURL.Host
		wildcardIndex := strings.Index(path, "*")
		proxyPath := singleJoiningSlash(originURL.Path, req.URL.Path[wildcardIndex:])
		if strings.HasSuffix(proxyPath, "/") && len(proxyPath) > 1 {
			proxyPath = proxyPath[:len(proxyPath)-1]
		}
		log.Debugln("req.URL.Path", req.URL.Path, "=>", proxyPath)
		req.URL.Path = proxyPath
	}
	router.Handle("GET", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		reverseProxy.ServeHTTP(w, r)
	})
	router.Handle("POST", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		reverseProxy.ServeHTTP(w, r)
	})
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
	delete(proxyMap, path)
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

	res = &api.RouteResponse{
		Message: req.Message,
		Status:  "OK",
	}

	return res, nil
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

package server

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/k8sopenstack"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
)

//Server for GRPC
type Server struct{}

//Provision a kubernetes cluster on openstack for the given Tenant
func (srv *Server) Provision(ctx context.Context, req *api.ProvisionRequest) (res *api.ProvisionResponse, err error) {
	if len(req.Provisions) < 1 {
		return nil, fmt.Errorf("missing provisions")
	}
	if err := k8sopenstack.CreateKubernetesCluster(req.Provisions[0]); err != nil { ///XXX only one for now
		return nil, fmt.Errorf("can't create kubernetes cluster on openstack, %v", err)
	}

	res = &api.ProvisionResponse{
		Message: req.Message,
		Status:  "ok",
	}

	return res, nil
}

//Destroy a kubernetes cluster on openstack for the given Tenant
func (srv *Server) Destroy(ctx context.Context, req *api.ProvisionRequest) (res *api.ProvisionResponse, err error) {
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

//Proxy traffic betwwen kubernetes pods, via openstack subnet/network, iptables, and external network
func (srv *Server) Proxy(ctx context.Context, req *api.ProxyRequest) (res *api.ProxyResponse, err error) {
	res = &api.ProxyResponse{
		Message: req.Message,
	}

	return res, nil
}

//FQDN serves name to IP address mapping for potentially ephemeral kubernetes services/deployments/pods
func (srv *Server) FQDN(ctx context.Context, req *api.FQDNRequest) (res *api.FQDNResponse, err error) {
	res = &api.FQDNResponse{
		Message: req.Message,
	}

	return res, nil
}

//Status returns status information of the kubernetes cluster on openstack for a given tenant
func (srv *Server) Status(ctx context.Context, req *api.StatusRequest) (res *api.StatusResponse, err error) {
	res = &api.StatusResponse{
		Message: req.Message,
	}

	return res, nil
}

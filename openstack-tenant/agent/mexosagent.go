package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/server"
	log "github.com/sirupsen/logrus"
)

//Agent lives on a KVM inside cloudlet. It can talk with kubernetes cluster.
//Agent needs to be on a node that has external network and internal network(s).
//It can proxy traffic between networks and terminates TLS.
//Each private subnet added requires additional routing table entry on the node.
//Originally agent had provisioning code which initialized rudimentary kubernetes cluster.
//It no longer has this function, which is pushed further out to the CRM side.
//This is due to platform dependent issues, as well as to allow more automation.
func main() {
	fmt.Println(os.Args)
	cert := flag.String("cert", "/var/www/.cache", "directory holding certificates and keys")
	debug := flag.Bool("debug", false, "debug")
	grpcAddress := flag.String("grpc", ":18888", "GRPC address")
	restAddress := flag.String("rest", ":18889", "REST API address")
	proxyAddress := flag.String("proxy", ":443", "Proxy server address")
	flag.Parse()
	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	//XXX TODO make logrus use a log daemon to log to remote server
	log.Debugf("starting HTTP Server at %s", *restAddress)
	go func() {
		if *proxyAddress != "" {
			log.Debugf("starting Proxy server at %s", *proxyAddress)
			err := http.ListenAndServeTLS(*proxyAddress, *cert+"/cert.pem", *cert+"/key.pem", server.GetNewRouter())
			if err != nil {
				log.Fatalf("cannot run proxy server, %v", err)
			}
		}
	}()
	log.Debugf("starting GRPC Server at %s", *grpcAddress)
	go func() {
		if err := server.ListenAndServeGRPC(*grpcAddress); err != nil {
			log.Fatalf("cannot run GRPC server, %v", err)
		}
	}()
	err := server.ListenAndServeREST(*restAddress, *grpcAddress)
	if err != nil {
		log.Fatalf("cannot run HTTP server, %v", err)
	}
}

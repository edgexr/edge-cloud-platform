package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	log "github.com/bobbae/logrus"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/server"
)

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

	log.Debugf("starting HTTP Server at %s", *restAddress)
	go func() {
		err := server.ListenAndServeREST(*restAddress, *grpcAddress)
		if err != nil {
			log.Fatalf("cannot run HTTP server, %v", err)
		}
	}()

	log.Debugf("starting GRPC Server at %s", *grpcAddress)
	go func() {
		if err := server.ListenAndServeGRPC(*grpcAddress); err != nil {
			log.Fatalf("cannot run GRPC server, %v", err)
		}
	}()

	log.Debugf("starting Proxy server at %s", *proxyAddress)
	log.Fatal(http.ListenAndServeTLS(*proxyAddress, *cert+"/cert.pem", *cert+"/key.pem", nil))
}

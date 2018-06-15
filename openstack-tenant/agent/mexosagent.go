package main

import (
	"flag"

	log "github.com/bobbae/logrus"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/server"
)

func main() {
	grpcAddress := flag.String("grpc", ":18888", "GRPC bind address")
	restAddress := flag.String("http", ":18889", "HTTP bind address")
	debug := flag.Bool("debug", false, "Produce debug log messages")

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

	if err := server.ListenAndServeGRPC(*grpcAddress); err != nil {
		log.Fatalf("cannot run GRPC server, %v", err)
	}
}

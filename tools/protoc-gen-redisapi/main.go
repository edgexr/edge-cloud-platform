package main

import "github.com/edgexr/edge-cloud-platform/pkg/gensupport"

func main() {
	plugin := RedisAPIGen{}
	gensupport.RunMain("rediscache", ".redisapi.go", &plugin, &plugin.support)
}

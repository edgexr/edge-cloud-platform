package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/parnurzeal/gorequest"
)

//AddPathReverseProxy adds a new route to origin on the reverse proxy
func AddPathReverseProxy(rootLBName, path, origin string) []error {
	log.DebugLog(log.DebugLevelMexos, "add path to reverse proxy", "rootlbname", rootLBName, "path", path, "origin", origin)
	if path == "" {
		return []error{fmt.Errorf("empty path")}
	}
	if origin == "" {
		return []error{fmt.Errorf("empty origin")}
	}
	request := gorequest.New()
	maURI := fmt.Sprintf("http://%s:%s/v1/proxy", rootLBName, GetCloudletMexosAgentPort())
	// The L7 reverse proxy terminates TLS at the RootLB and uses path routing to get to the service at a IP:port
	pl := fmt.Sprintf(`{ "message": "add", "proxies": [ { "path": "/%s/*catchall", "origin": "%s" } ] }`, path, origin)
	resp, body, errs := request.Post(maURI).Set("Content-Type", "application/json").Send(pl).End()
	if errs != nil {
		return errs
	}
	if strings.Contains(body, "OK") {
		log.DebugLog(log.DebugLevelMexos, "added path to revproxy")
		return nil
	}
	errs = append(errs, fmt.Errorf("resp %v, body %s", resp, body))
	return errs
}

//DeletePathReverseProxy Deletes a new route to origin on the reverse proxy
func DeletePathReverseProxy(rootLBName, path, origin string) []error {
	log.DebugLog(log.DebugLevelMexos, "delete path reverse proxy", "path", path, "origin", origin)
	//TODO
	return nil
}

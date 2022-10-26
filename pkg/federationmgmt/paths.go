package federationmgmt

import (
	"fmt"
	"net/http"
)

func PathCreateAppInst(fedCtxId string) (string, string) {
	return http.MethodPost, fmt.Sprintf("/%s/application/lcm", fedCtxId)
}

func PathGetAppInst(fedCtxId, appId, appInstId, zoneId string) (string, string) {
	return http.MethodGet, fmt.Sprintf("/%s/application/lcm/app/%s/instance/%s/zone/%s", fedCtxId, appId, appInstId, zoneId)
}

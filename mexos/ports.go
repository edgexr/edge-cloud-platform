package mexos

import (
	"fmt"
	"strings"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func GetPortDetail(appInst *edgeproto.AppInst) ([]PortDetail, error) {
	ports := make([]PortDetail, 0)
	for ii := range appInst.MappedPorts {
		port := &appInst.MappedPorts[ii]
		mexproto, ok := dme.LProto_name[int32(port.Proto)]
		if !ok {
			return nil, fmt.Errorf("invalid LProto %d", port.Proto)
		}
		proto := "UDP"
		if port.Proto != dme.LProto_LProtoUDP {
			proto = "TCP"
		}
		p := PortDetail{
			Name:         fmt.Sprintf("%s%d", strings.ToLower(mexproto), port.InternalPort),
			MexProto:     mexproto,
			Proto:        proto,
			InternalPort: int(port.InternalPort),
			PublicPort:   int(port.PublicPort),
			PublicPath:   port.PublicPath,
		}
		ports = append(ports, p)
	}
	return ports, nil
}

package mexos

import (
	"fmt"
	"strings"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func addPorts(mf *Manifest, appInst *edgeproto.AppInst) error {
	for ii, _ := range appInst.MappedPorts {
		port := &appInst.MappedPorts[ii]
		if mf.Spec.Ports == nil {
			mf.Spec.Ports = make([]PortDetail, 0)
		}
		mexproto, ok := dme.LProto_name[int32(port.Proto)]
		if !ok {
			return fmt.Errorf("invalid LProto %d", port.Proto)
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
		mf.Spec.Ports = append(mf.Spec.Ports, p)
	}
	return nil
}

package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

// ConvertNBIApp converts an NBI App model to an edgeproto App.
// We have very similar code in edge-cloud-director/pkg/mc/federation/fed_artefact.go
// that converts an Artefact (Federation equivalent of App) to an edgeproto App.
func ConvertNBIApp(in *nbi.AppManifest) (*edgeproto.App, error) {
	out := &edgeproto.App{}
	out.Key.Name = in.Name
	out.Key.Organization = "" // in.AppProvider missing
	out.Key.Version = strconv.Itoa(in.Version)
	switch in.PackageType {
	case nbi.CONTAINER:
		// use kubernetes, no way to do Docker deployments
		out.Deployment = cloudcommon.DeploymentTypeKubernetes
	case nbi.HELM:
		out.Deployment = cloudcommon.DeploymentTypeHelm
	case nbi.OVA:
		out.Deployment = cloudcommon.DeploymentTypeVM
		out.ImageType = edgeproto.ImageType_IMAGE_TYPE_OVA
	case nbi.QCOW2:
		out.Deployment = cloudcommon.DeploymentTypeVM
		out.ImageType = edgeproto.ImageType_IMAGE_TYPE_QCOW
	}
	out.Deployment = "" // no deployment type
	out.ImagePath = in.AppRepo.ImagePath
	if in.AppRepo.Type == nbi.PRIVATEREPO {
		// TODO: copy in to our local container repo
		return nil, fmt.Errorf("private repo type is not supported yet")
	}
	if in.AppRepo.Checksum != nil {
		// TODO: verify in.AppRepo.Checksum
	}
	if len(in.ComponentSpec) != 1 {
		return nil, fmt.Errorf("one and only one component spec must be specified")
	}
	ports := []string{}
	for _, intf := range in.ComponentSpec[0].NetworkInterfaces {
		if intf.VisibilityType == nbi.VISIBILITYINTERNAL {
			continue
		}
		// TODO: assume TLS
		if intf.Protocol == nbi.TCP || intf.Protocol == nbi.ANY {
			ports = append(ports, fmt.Sprintf("tcp:%d:tls", intf.Port))
		}
		if intf.Protocol == nbi.UDP || intf.Protocol == nbi.ANY {
			ports = append(ports, fmt.Sprintf("udp:%d:tls", intf.Port))
		}
	}
	out.AccessPorts = strings.Join(ports, ",")
	return out, nil
}

func (s *NBIAPIs) SubmitApp(ctx context.Context, request nbi.SubmitAppRequestObject) (nbi.SubmitAppResponseObject, error) {
	in, err := ConvertNBIApp(request.Body)
	if err == nil {
		_, err = s.allApis.appApi.CreateApp(ctx, in) // TODO: maybe add http codes to Result for errors?
	}
	if err != nil {
		if strings.Contains(err.Error(), in.Key.ExistsError().Error()) {
			return nbi.SubmitApp409JSONResponse{
				Message: err.Error(),
			}, nil
		}
		return nbi.SubmitApp400JSONResponse{
			N400JSONResponse: nbi.N400JSONResponse{
				Body: nbi.ErrorInfo{
					Message: err.Error(),
				},
			},
		}, nil
	}
	appID := nbi.AppId(in.GlobalId) // EWBI uses string instead of UUID
	return nbi.SubmitApp201JSONResponse{
		Body: nbi.SubmittedApp{
			AppId: &appID,
		},
	}, nil
}

func (s *NBIAPIs) DeleteApp(ctx context.Context, request nbi.DeleteAppRequestObject) (nbi.DeleteAppResponseObject, error) {

}
func (s *NBIAPIs) GetApp(ctx context.Context, request nbi.GetAppRequestObject) (nbi.GetAppResponseObject, error) {

}
func (s *NBIAPIs) GetAppInstance(ctx context.Context, request nbi.GetAppInstanceRequestObject) (nbi.GetAppInstanceResponseObject, error) {

}
func (s *NBIAPIs) CreateAppInstance(ctx context.Context, request nbi.CreateAppInstanceRequestObject) (nbi.CreateAppInstanceResponseObject, error) {

}

func (s *NBIAPIs) DeleteAppInstance(ctx context.Context, request nbi.DeleteAppInstanceRequestObject) (nbi.DeleteAppInstanceResponseObject, error) {

}

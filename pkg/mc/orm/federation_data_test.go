package orm

import (
	fmt "fmt"
	"testing"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/stretchr/testify/require"
)

// test data for federation unit tests

func getConsImages(org, fedName string) []*ormapi.ConsumerImage {
	return []*ormapi.ConsumerImage{{
		Organization:   org,
		FederationName: fedName,
		SourcePath:     "https://public.io/some/path/public.img",
		Type:           string(fedewapi.VIRTIMAGETYPE_QCOW2),
		Checksum:       "abcdefg09123",
	}, {
		Organization:   org,
		FederationName: fedName,
		Name:           "pub:1.0.1",
		SourcePath:     "some/path/public:1.0.1",
		Type:           string(fedewapi.VIRTIMAGETYPE_DOCKER),
		Checksum:       "sha256:abcdefg21309873",
	}}
}

func getConsApps(org string) []edgeproto.App {
	return []edgeproto.App{{
		Key: edgeproto.AppKey{
			Organization: org,
			Name:         "dockerapp",
			Version:      "1.0.0",
		},
		ImageType:   edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		ImagePath:   "org/image:v1.3.0",
		Md5Sum:      "sha256:209f09fg090923",
		Deployment:  cloudcommon.DeploymentTypeKubernetes,
		FederatedId: "region-dockerapp100org",
	}, {
		Key: edgeproto.AppKey{
			Organization: org,
			Name:         "vmapp",
			Version:      "1.0.0",
		},
		ImageType:   edgeproto.ImageType_IMAGE_TYPE_QCOW,
		ImagePath:   "https://vm.com/org/image.img",
		Md5Sum:      "309fa098fb0983309",
		Deployment:  cloudcommon.DeploymentTypeVM,
		FederatedId: "region-vmapp100org",
	}}
}

// Image created via the ConsApps
func getConsAppImages(t *testing.T, org, fedName string) []*ormapi.ConsumerImage {
	images := []*ormapi.ConsumerImage{}
	for _, app := range getConsApps(org) {
		forapp, err := getImagesForApp(fedName, &app)
		require.Nil(t, err)
		images = append(images, forapp...)
	}
	return images
}

type FrmData struct {
	consApp         edgeproto.App
	consClusterInst edgeproto.ClusterInst
	consAppInst     edgeproto.AppInst
	provAppInst     edgeproto.AppInst
}

func getFrmData(consAttr, provAttr *FederatorAttr, zones []string) []FrmData {
	apps := getConsApps(consAttr.developerId)

	frmData := []FrmData{}
	for ii, zone := range zones {
		for _, app := range apps {
			consCloudletKey := edgeproto.CloudletKey{
				Name:                  zone,
				Organization:          consAttr.fedName,
				FederatedOrganization: consAttr.operatorId,
			}
			consClust := edgeproto.ClusterInst{}
			consClust.Key.ClusterKey.Name = fmt.Sprintf("reservable%d", ii)
			consClust.Key.CloudletKey = consCloudletKey
			consClust.Key.Organization = edgeproto.OrganizationEdgeCloud

			consAi := edgeproto.AppInst{}
			consAi.Key.AppKey.Name = app.Key.Name
			consAi.Key.AppKey.Organization = app.Key.Organization
			consAi.Key.AppKey.Version = app.Key.Version
			consAi.Key.ClusterInstKey = *consClust.Key.Virtual(fmt.Sprintf("autocluster%d", ii))

			provAi := edgeproto.AppInst{}

			data := FrmData{
				consApp:         app,
				consClusterInst: consClust,
				consAppInst:     consAi,
				provAppInst:     provAi,
			}
			frmData = append(frmData, data)
		}

	}
	return frmData
}

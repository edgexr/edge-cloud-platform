package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//MEXClusterCreateClustInst calls MEXClusterCreate with a manifest created from the template
func MEXClusterCreateClustInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) error {
	//XXX trigger off clusterInst or flavor to pick the right template: mex, aks, gke
	mf, err := FillClusterTemplateClustInst(rootLB, clusterInst)
	if err != nil {
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXClusterCreateManifest(mf)
}

//MEXClusterRemoveClustInst calls MEXClusterRemove with a manifest created from the template
func MEXClusterRemoveClustInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) error {
	mf, err := FillClusterTemplateClustInst(rootLB, clusterInst)
	if err != nil {
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXClusterRemoveManifest(mf)
}

func FillClusterTemplateClustInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) (*Manifest, error) {
	log.DebugLog(log.DebugLevelMexos, "fill cluster template manifest cluster inst", "clustinst", clusterInst)
	if clusterInst.Key.ClusterKey.Name == "" {
		log.DebugLog(log.DebugLevelMexos, "cannot create empty cluster manifest", "clustinst", clusterInst)
		return nil, fmt.Errorf("invalid cluster inst %v", clusterInst)
	}
	if verr := ValidateClusterKind(clusterInst.Key.CloudletKey.OperatorKey.Name); verr != nil {
		return nil, verr
	}
	vp := &rootLB.PlatConf.Values
	data := templateFill{
		ResourceKind:  "cluster",
		Resource:      clusterInst.Flavor.Name,
		Name:          clusterInst.Key.ClusterKey.Name,
		Tags:          clusterInst.Key.ClusterKey.Name + "-tag",
		Tenant:        clusterInst.Key.ClusterKey.Name + "-tenant",
		Operator:      NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name),
		Key:           clusterInst.Key.ClusterKey.Name,
		Kind:          vp.Cluster.Kind, //"kubernetes",
		ResourceGroup: clusterInst.Key.CloudletKey.Name + "_" + clusterInst.Key.ClusterKey.Name,
		Flavor:        clusterInst.Flavor.Name,
		DNSZone:       vp.Network.DNSZone, //"mobiledgex.net",
		RootLB:        rootLB.Name,
		Region:        vp.Cluster.Region,   //us-west1
		Zone:          vp.Cluster.Zone,     //us-west1a
		Location:      vp.Cluster.Location, // us-west
		NetworkScheme: vp.Network.Scheme,   //"priv-subnet,mex-k8s-net-1,10.101.X.0/24",
		Swarm:         vp.Cluster.Swarm,
	}

	// // if these env variables are not set, fall back to the
	// // existing defaults based on deployment type(operator name)
	// data.Region = os.Getenv("CLOUDLET_REGION")
	// data.Zone = os.Getenv("CLOUDLET_ZONE")
	// data.Location = os.Getenv("CLOUDLET_LOCATION")

	// switch clusterInst.Key.CloudletKey.OperatorKey.Name {
	// case "gcp":
	// 	if data.Region == "" {
	// 		data.Region = "us-west1"
	// 	}
	// 	if data.Zone == "" {
	// 		data.Zone = "us-west1-a"
	// 	}
	// 	if data.Location == "" {
	// 		data.Location = "us-west"
	// 	}
	// 	data.Project = "still-entity-201400" // XXX
	// case "azure":
	// 	if data.Region == "" {
	// 		data.Region = "centralus"
	// 	}
	// 	if data.Zone == "" {
	// 		data.Zone = "centralus"
	// 	}
	// 	if data.Location == "" {
	// 		data.Location = "centralus"
	// 	}
	// default:
	// 	if data.Region == "" {
	// 		data.Region = "eu-central-1"
	// 	}
	// 	if data.Zone == "" {
	// 		data.Zone = "eu-central-1c"
	// 	}
	// 	if data.Location == "" {
	// 		data.Location = "buckhorn"
	// 	}
	// }

	mf, err := templateUnmarshal(&data, yamlMEXCluster)
	if err != nil {
		return nil, err
	}
	fixValuesInst(mf, rootLB)
	return mf, nil
}

func MEXAddFlavorClusterInst(rootLB *MEXRootLB, flavor *edgeproto.ClusterFlavor) error {
	log.DebugLog(log.DebugLevelMexos, "adding cluster inst flavor", "flavor", flavor)

	if flavor.Key.Name == "" {
		log.DebugLog(log.DebugLevelMexos, "cannot add empty cluster inst flavor", "flavor", flavor)
		return fmt.Errorf("will not add empty cluster inst %v", flavor)
	}
	vp := &rootLB.PlatConf.Values
	data := templateFill{
		ResourceKind:  "flavor",
		Resource:      flavor.Key.Name,
		Name:          flavor.Key.Name,
		Tags:          flavor.Key.Name + "-tag",
		Kind:          vp.Cluster.Kind,
		Flags:         flavor.Key.Name + "-flags",
		NumNodes:      int(flavor.NumNodes),
		NumMasters:    int(flavor.NumMasters),
		NetworkScheme: vp.Network.Scheme,
		MasterFlavor:  flavor.MasterFlavor.Name,
		NodeFlavor:    flavor.NodeFlavor.Name,
		StorageSpec:   "default", //XXX
		Topology:      "type-1",  //XXX
	}
	mf, err := templateUnmarshal(&data, yamlMEXFlavor)
	if err != nil {
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXAddFlavor(mf)
}

//MEXAppCreateAppInst creates app inst with templated manifest
func MEXAppCreateAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, app *edgeproto.App) error {
	log.DebugLog(log.DebugLevelMexos, "mex create app inst", "rootlb", rootLB.Name, "clusterinst", clusterInst, "appinst", appInst)
	mf, err := fillAppTemplate(rootLB, appInst, app, clusterInst)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "fillAppTemplate error", "error", err)
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXAppCreateAppManifest(mf)
}

//MEXAppDeleteAppInst deletes app with templated manifest
func MEXAppDeleteAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, app *edgeproto.App) error {
	log.DebugLog(log.DebugLevelMexos, "mex delete app inst", "rootlb", rootLB.Name, "clusterinst", clusterInst, "appinst", appInst)
	mf, err := fillAppTemplate(rootLB, appInst, app, clusterInst)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "fillAppTemplate error", "error", err)
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXAppDeleteAppManifest(mf)
}

func fixValuesInst(mf *Manifest, rootLB *MEXRootLB) error {
	if mf.Values.Kind == "" {
		mf.Values = rootLB.PlatConf.Values
	}
	if mf.Values.Kind == "" {
		log.DebugLog(log.DebugLevelMexos, "warning, missing mf values")
	}
	return nil
}

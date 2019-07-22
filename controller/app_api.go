// app config

package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/objstore"
	"github.com/mobiledgex/edge-cloud/util"
)

// Should only be one of these instantiated in main
type AppApi struct {
	sync  *Sync
	store edgeproto.AppStore
	cache edgeproto.AppCache
}

var appApi = AppApi{}

func InitAppApi(sync *Sync) {
	appApi.sync = sync
	appApi.store = edgeproto.NewAppStore(sync.store)
	edgeproto.InitAppCache(&appApi.cache)
	sync.RegisterCache(&appApi.cache)
}

func (s *AppApi) HasApp(key *edgeproto.AppKey) bool {
	return s.cache.HasKey(key)
}

func (s *AppApi) GetAllKeys(keys map[edgeproto.AppKey]struct{}) {
	s.cache.GetAllKeys(keys)
}

func (s *AppApi) Get(key *edgeproto.AppKey, buf *edgeproto.App) bool {
	return s.cache.Get(key, buf)
}

func (s *AppApi) UsesDeveloper(in *edgeproto.DeveloperKey) bool {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for key, app := range s.cache.Objs {
		if key.DeveloperKey.Matches(in) && app.DelOpt != edgeproto.DeleteType_AUTO_DELETE {
			return true
		}
	}
	return false
}

func (s *AppApi) UsesFlavor(key *edgeproto.FlavorKey) bool {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, app := range s.cache.Objs {
		if app.DefaultFlavor.Matches(key) && app.DelOpt != edgeproto.DeleteType_AUTO_DELETE {
			return true
		}
	}
	return false
}

func (s *AppApi) AutoDeleteAppsForDeveloper(ctx context.Context, key *edgeproto.DeveloperKey) {
	apps := make(map[edgeproto.AppKey]*edgeproto.App)
	log.DebugLog(log.DebugLevelApi, "Auto-deleting apps ", "developer", key)
	s.cache.Mux.Lock()
	for k, app := range s.cache.Objs {
		if app.Key.DeveloperKey.Matches(key) && app.DelOpt == edgeproto.DeleteType_AUTO_DELETE {
			apps[k] = app
		}
	}
	s.cache.Mux.Unlock()
	for _, val := range apps {
		log.DebugLog(log.DebugLevelApi, "Auto-deleting app ", "app", val.Key.Name)
		if _, err := s.DeleteApp(ctx, val); err != nil {
			log.DebugLog(log.DebugLevelApi, "unable to auto-delete app", "app", val, "err", err)
		}
	}
}

func (s *AppApi) AutoDeleteApps(ctx context.Context, key *edgeproto.FlavorKey) {
	apps := make(map[edgeproto.AppKey]*edgeproto.App)
	log.DebugLog(log.DebugLevelApi, "Auto-deleting apps ", "flavor", key)
	s.cache.Mux.Lock()
	for k, app := range s.cache.Objs {
		if app.DefaultFlavor.Matches(key) && app.DelOpt == edgeproto.DeleteType_AUTO_DELETE {
			apps[k] = app
		}
	}
	s.cache.Mux.Unlock()
	for _, val := range apps {
		log.DebugLog(log.DebugLevelApi, "Auto-deleting app ", "app", val.Key.Name)
		if _, err := s.DeleteApp(ctx, val); err != nil {
			log.DebugLog(log.DebugLevelApi, "unable to auto-delete app", "app", val, "err", err)
		}
	}
}

// AndroidPackageConflicts returns true if an app with a different developer+name
// has the same package.  It is expect that different versions of the same app with
// the same package however so we do not do a full key comparison
func (s *AppApi) AndroidPackageConflicts(a *edgeproto.App) bool {
	if a.AndroidPackageName == "" {
		return false
	}
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, app := range s.cache.Objs {
		if app.AndroidPackageName == a.AndroidPackageName {
			if (a.Key.DeveloperKey.Name != app.Key.DeveloperKey.Name) || (a.Key.Name != app.Key.Name) {
				return true
			}
		}
	}
	return false
}

// updates fields that need manipulation on setting, or fetched remotely. Updates the revision only if something changed
func updateAppFields(in *edgeproto.App, revision int32) error {

	// keep a copy of the old app so we can see if it changed.   This could be if we specifically modified a field,
	// or the contents that we pull from a remove manifest changed
	var oldApp = *in

	if in.ImagePath == "" {
		if in.ImageType == edgeproto.ImageType_IMAGE_TYPE_DOCKER {
			in.ImagePath = *registryFQDN + "/" +
				util.DockerSanitize(in.Key.DeveloperKey.Name) + "/images/" +
				util.DockerSanitize(in.Key.Name) + ":" +
				util.DockerSanitize(in.Key.Version)
		} else if in.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
			return fmt.Errorf("imagepath is required for imagetype %s", in.ImageType)
		} else if in.Deployment == cloudcommon.AppDeploymentTypeHelm {
			in.ImagePath = *registryFQDN + "/" +
				util.DockerSanitize(in.Key.DeveloperKey.Name) + "/images/" +
				util.DockerSanitize(in.Key.Name)
		} else {
			in.ImagePath = "qcow path not determined yet"
		}
	}

	if !cloudcommon.IsPlatformApp(in.Key.DeveloperKey.Name, in.Key.Name) {
		if in.ImageType == edgeproto.ImageType_IMAGE_TYPE_DOCKER {
			parts := strings.Split(in.ImagePath, "/")
			// Append default registry address for internal image paths
			if len(parts) < 2 || !strings.Contains(parts[0], ".") {
				return fmt.Errorf("imagepath should be full registry URL: <domain-name>/<registry-path>")
			}
			if !*testMode {
				err := cloudcommon.ValidateDockerRegistryPath(in.ImagePath, *vaultAddr)
				if err != nil {
					return err
				}
			}
		}
	}

	if in.ScaleWithCluster && in.Deployment != cloudcommon.AppDeploymentTypeKubernetes {
		return fmt.Errorf("app scaling is only supported for Kubernetes deployments")
	}

	if in.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
		if !*testMode {
			err := cloudcommon.ValidateVMRegistryPath(in.ImagePath, *vaultAddr)
			if err != nil {
				return err
			}
		}
		err := util.ValidateImagePath(in.ImagePath)
		if err != nil {
			return err
		}
	}

	// for update, trigger regenerating deployment manifest
	if in.DeploymentGenerator != "" {
		in.DeploymentManifest = ""
	}

	deploymf, err := cloudcommon.GetAppDeploymentManifest(in)
	if err != nil {
		return err
	}
	// Save manifest to app in case it was a remote target.
	// Manifest is required on app delete and we'll be in trouble
	// if remote target is unreachable or changed at that time.
	in.DeploymentManifest = deploymf

	if reflect.DeepEqual(oldApp, *in) {
		log.DebugLog(log.DebugLevelApi, "no changes in app, maintaining old revision")
	} else {
		log.DebugLog(log.DebugLevelApi, "app was modified, updating revision", "revision", revision)
		in.Revision = revision
	}
	return nil
}

func (s *AppApi) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	var err error

	if err = in.Validate(edgeproto.AppAllFieldsMap); err != nil {
		return &edgeproto.Result{}, err
	}
	if in.Deployment == "" {
		in.Deployment, err = cloudcommon.GetDefaultDeploymentType(in.ImageType)
		if err != nil {
			return &edgeproto.Result{}, err
		}
	}
	if !cloudcommon.IsValidDeploymentType(in.Deployment) {
		return &edgeproto.Result{}, fmt.Errorf("invalid deployment, must be one of %v", cloudcommon.ValidDeployments)
	}
	if !cloudcommon.IsValidDeploymentForImage(in.ImageType, in.Deployment) {
		return &edgeproto.Result{}, fmt.Errorf("deployment is not valid for image type")
	}
	if in.Deployment == cloudcommon.AppDeploymentTypeDocker {
		if in.AccessPorts != "" {
			if strings.Contains(in.AccessPorts, "http") {
				return &edgeproto.Result{}, fmt.Errorf("Deployment Type Docker and HTTP access ports are incompatable")
			}
		}
	}
	err = updateAppFields(in, 0)
	if err != nil {
		return &edgeproto.Result{}, err
	}
	if in.DeploymentManifest != "" {
		err = cloudcommon.IsValidDeploymentManifest(in.Deployment, in.Command, in.DeploymentManifest)
		if err != nil {
			return &edgeproto.Result{}, fmt.Errorf("invalid deploymentment manifest %v", err)
		}
	}

	if s.AndroidPackageConflicts(in) {
		return &edgeproto.Result{}, fmt.Errorf("AndroidPackageName: %s in use by another app", in.AndroidPackageName)
	}

	err = s.sync.ApplySTMWait(func(stm concurrency.STM) error {
		if !flavorApi.store.STMGet(stm, &in.DefaultFlavor, nil) {
			return edgeproto.ErrEdgeApiFlavorNotFound
		}
		if s.store.STMGet(stm, &in.Key, nil) {
			return objstore.ErrKVStoreKeyExists
		}
		s.store.STMPut(stm, in)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *AppApi) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	if s.AndroidPackageConflicts(in) {
		return &edgeproto.Result{}, fmt.Errorf("AndroidPackageName: %s in use by another app", in.AndroidPackageName)
	}

	// if the app is already deployed, there are restrictions on what can be changed.
	dynInsts := make(map[edgeproto.AppInstKey]struct{})
	appInstExists := false
	if appInstApi.UsesApp(&in.Key, dynInsts) {
		appInstExists = true
		for _, field := range in.Fields {
			if field == edgeproto.AppFieldAccessPorts ||
				field == edgeproto.AppFieldDeployment {
				return &edgeproto.Result{}, fmt.Errorf("Field cannot be modified when AppInstances exist")
			}
		}
	}

	err := s.sync.ApplySTMWait(func(stm concurrency.STM) error {
		cur := edgeproto.App{}

		if !s.store.STMGet(stm, &in.Key, &cur) {
			return objstore.ErrKVStoreKeyNotFound
		}
		if appInstExists {
			if cur.Deployment != cloudcommon.AppDeploymentTypeKubernetes &&
				cur.Deployment != cloudcommon.AppDeploymentTypeDocker {
				return fmt.Errorf("UpdateApp not supported for deployment: %s when AppInstances exist", cur.Deployment)
			}
		}
		cur.CopyInFields(in)
		newRevision := cur.Revision + 1
		if err := updateAppFields(&cur, newRevision); err != nil {
			return err
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *AppApi) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	if !appApi.HasApp(&in.Key) {
		// key doesn't exist
		return &edgeproto.Result{}, objstore.ErrKVStoreKeyNotFound
	}
	dynInsts := make(map[edgeproto.AppInstKey]struct{})
	if appInstApi.UsesApp(&in.Key, dynInsts) {
		// disallow delete if static instances are present
		return &edgeproto.Result{}, errors.New("Application in use by static Application Instance")
	}
	err := s.sync.ApplySTMWait(func(stm concurrency.STM) error {
		app := edgeproto.App{}
		if !s.store.STMGet(stm, &in.Key, &app) {
			// already deleted
			return nil
		}
		// delete app
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	if err == nil && len(dynInsts) > 0 {
		// delete dynamic instances
		for key, _ := range dynInsts {
			appInst := edgeproto.AppInst{Key: key}
			derr := appInstApi.DeleteAppInst(&appInst, nil)
			if derr != nil {
				log.DebugLog(log.DebugLevelApi,
					"Failed to delete dynamic app inst",
					"err", derr)
			}
		}
	}
	return &edgeproto.Result{}, err
}

func (s *AppApi) ShowApp(in *edgeproto.App, cb edgeproto.AppApi_ShowAppServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.App) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

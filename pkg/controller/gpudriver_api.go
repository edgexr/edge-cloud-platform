// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type GPUDriverApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.GPUDriverStore
	cache edgeproto.GPUDriverCache
}

const (
	GPUDriverBuildURLValidity = 20 * time.Minute
	ChangeInProgress          = "ChangeInProgress"
	AllCloudlets              = ""
)

func NewGPUDriverApi(sync *regiondata.Sync, all *AllApis) *GPUDriverApi {
	gpuDriverApi := GPUDriverApi{}
	gpuDriverApi.all = all
	gpuDriverApi.sync = sync
	gpuDriverApi.store = edgeproto.NewGPUDriverStore(sync.GetKVStore())
	edgeproto.InitGPUDriverCache(&gpuDriverApi.cache)
	sync.RegisterCache(&gpuDriverApi.cache)
	return &gpuDriverApi
}

func validateGPUDriver(ctx context.Context, driver *edgeproto.GPUDriver, build *edgeproto.GPUDriverBuild, cb edgeproto.GPUDriverApi_CreateGPUDriverServer) error {
	if build.DriverPath == "" {
		return fmt.Errorf("Missing driverpath: %s", build.Name)
	}
	if build.OperatingSystem == edgeproto.OSType_LINUX && build.KernelVersion == "" {
		return fmt.Errorf("Kernel version is required for Linux build %s", build.Name)
	}
	driverFileName, err := cloudcommon.GetFileNameWithExt(build.DriverPath)
	if err != nil {
		return err
	}
	ext := filepath.Ext(driverFileName)
	// Download the driver package
	authApi := cloudcommon.NewVaultRegistryAuthApi(*region, services.regAuthMgr)
	cb.Send(&edgeproto.Result{Message: "Checking GPU driver build " + build.Name})
	fileName := build.StoragePath
	localFilePath := "/tmp/" + strings.ReplaceAll(fileName, "/", "_")
	err = cloudcommon.DownloadFile(ctx, authApi, nil, build.DriverPath, build.DriverPathCreds, localFilePath, nil)
	if err != nil {
		return fmt.Errorf("Failed to download GPU driver build %s, %v", build.DriverPath, err)
	}
	defer cloudcommon.DeleteFile(localFilePath)
	cb.Send(&edgeproto.Result{Message: "Validating MD5Sum of the package"})
	md5sum, err := cloudcommon.Md5SumFile(localFilePath)
	if err != nil {
		return err
	}
	if build.Md5Sum != md5sum {
		return fmt.Errorf("Invalid md5sum specified, expected md5sum %s", md5sum)
	}

	// If Linux, then validate the pkg
	//     * Pkg must be deb pkg
	//     * Pkg control file must have kernel dependency specified
	if build.OperatingSystem == edgeproto.OSType_LINUX {
		cb.Send(&edgeproto.Result{Message: "Verifying if GPU driver package is a debian package"})
		if ext != ".deb" {
			return fmt.Errorf("Only supported file extension for Linux GPU driver is '.deb', given %s", ext)
		}
		cb.Send(&edgeproto.Result{Message: "Verifying if kernel dependency is specified as part of package's control file"})
		localClient := &pc.LocalClient{}
		cmd := fmt.Sprintf("dpkg-deb -I %s | grep -i 'Depends: linux-image-%s'", localFilePath, build.KernelVersion)
		out, err := localClient.Output(cmd)
		if err != nil && out != "" {
			return fmt.Errorf("Invalid driver package(%q), should be a valid debian package, %s, %v", fileName, out, err)
		}
		if out == "" {
			return fmt.Errorf("Driver package(%q) should have Linux Kernel dependency(%q) specified as part of debian control file, %v", fileName, build.KernelVersion, err)
		}
	}

	build.StoragePath, err = cloudcommon.GetGPUDriverBuildStoragePath(&driver.Key, *region, build.Name, ext)
	if err != nil {
		return err
	}

	return nil
}

func (s *GPUDriverApi) validateLicenseConfig(ctx context.Context, licenseConfig string, md5sum *string) error {
	if licenseConfig == "" {
		return nil
	}
	_, err := util.ImagePathParse(licenseConfig)
	if err != nil {
		return fmt.Errorf("failed to parse LicenseConfig URL %s, %s", licenseConfig, err)
	}
	// check if its accessible
	authApi := cloudcommon.NewVaultRegistryAuthApi(*region, services.regAuthMgr)
	reqConfig := &cloudcommon.RequestConfig{
		Timeout: 3 * time.Second,
	}
	resp, err := cloudcommon.SendHTTPReq(ctx, http.MethodHead, licenseConfig, nil, authApi, "", reqConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to HEAD license config %s, %s", licenseConfig, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to HEAD license config %s, response %s", licenseConfig, resp.Status)
	}
	checksum := resp.Header.Get(cloudcommon.VmRegHeaderMD5)
	if checksum == "" {
		return errors.New("no MD5 checksum in HEAD response for " + licenseConfig)
	}
	*md5sum = checksum
	return nil
}

func (s *GPUDriverApi) validateGPUDriverLicense(ctx context.Context, in *edgeproto.GPUDriver) error {
	err := s.validateLicenseConfig(ctx, in.LicenseConfig, &in.LicenseConfigMd5Sum)
	if err != nil {
		return err
	}
	in.LicenseConfigStoragePath, err = cloudcommon.GetGPUDriverLicenseStoragePath(&in.Key, *region)
	if err != nil {
		return err
	}
	return nil
}

func (s *GPUDriverApi) undoStateChange(ctx context.Context, key *edgeproto.GPUDriverKey) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		driver := edgeproto.GPUDriver{}
		if !s.store.STMGet(stm, key, &driver) {
			return nil
		}
		driver.State = ""
		driver.DeletePrepare = false
		s.store.STMPut(stm, &driver)
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to undo state change", "key", key, "err", err)
	}
}

func (s *GPUDriverApi) startGPUDriverStream(ctx context.Context, cctx *CallContext, streamCb *CbWrapper, modRev int64) (*streamSend, error) {
	streamSendObj, err := s.all.streamObjApi.startStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start GPU driver stream", "err", err)
		return nil, err
	}
	return streamSendObj, err
}

func (s *GPUDriverApi) stopGPUDriverStream(ctx context.Context, cctx *CallContext, key *edgeproto.GPUDriverKey, streamSendObj *streamSend, objErr error, cleanupStream CleanupStreamAction) {
	if err := s.all.streamObjApi.stopStream(ctx, cctx, key.StreamKey(), streamSendObj, objErr, cleanupStream); err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to stop GPU driver stream", "err", err)
	}
}

func (s *StreamObjApi) StreamGPUDriver(key *edgeproto.GPUDriverKey, cb edgeproto.StreamObjApi_StreamGPUDriverServer) error {
	return s.StreamMsgs(cb.Context(), key.StreamKey(), cb)
}

func (s *GPUDriverApi) CreateGPUDriver(in *edgeproto.GPUDriver, cb edgeproto.GPUDriverApi_CreateGPUDriverServer) (reterr error) {
	cctx := DefCallContext()
	ctx := cb.Context()
	if err := in.Validate(edgeproto.GPUDriverAllFieldsMap); err != nil {
		return err
	}

	if in.Key.Organization == "" {
		// Public GPU drivers have no org associated with them
	}

	gpuDriverKey := in.Key
	var err error
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, gpuDriverKey.StreamKey(), cb)

	// Step-1: First commit to etcd
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.ExistsError()
		}
		in.State = ChangeInProgress
		// Setup build storage paths
		for ii, build := range in.Builds {
			driverFileName, err := cloudcommon.GetFileNameWithExt(build.DriverPath)
			if err != nil {
				return err
			}
			ext := filepath.Ext(driverFileName)
			in.Builds[ii].StoragePath, err = cloudcommon.GetGPUDriverBuildStoragePath(&in.Key, *region, build.Name, ext)
			if err != nil {
				return err
			}
		}
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return err
	}

	defer func() {
		if reterr != nil {
			// undo changes
			err = s.deleteGPUDriverInternal(DefCallContext().WithUndo(), in, cb)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to undo gpu driver create", "key", in.Key, "err", err)
			}
		}
	}()

	sendObj, err := s.startGPUDriverStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr != nil {
			// Cleanup stream if object is not present in etcd (due to undo)
			if !s.store.Get(ctx, &in.Key, nil) {
				cleanupStream = CleanupStream
			}
		}
		s.stopGPUDriverStream(ctx, cctx, &gpuDriverKey, sendObj, reterr, cleanupStream)
	}()

	if len(in.Builds) > 0 {
		// Validate the builds
		for _, build := range in.Builds {
			cb.Send(&edgeproto.Result{Message: "Setting up GPU driver build " + build.Name})
			err := validateGPUDriver(ctx, in, &build, cb)
			if err != nil {
				return err
			}
		}
	}
	// license config must now be an URL to a file, typically
	// stored in the vm-registry
	if err := s.validateGPUDriverLicense(ctx, in); err != nil {
		return err
	}

	in.State = ""
	_, err = s.store.Put(ctx, in, s.sync.SyncWait)
	if err != nil {
		return err
	}
	cb.Send(&edgeproto.Result{Message: "GPU driver created successfully"})
	return nil
}

func (s *GPUDriverApi) UpdateGPUDriver(in *edgeproto.GPUDriver, cb edgeproto.GPUDriverApi_UpdateGPUDriverServer) (reterr error) {
	cctx := DefCallContext()
	ctx := cb.Context()
	err := in.ValidateUpdateFields()
	if err != nil {
		return err
	}
	fmap := edgeproto.MakeFieldMap(in.Fields)
	if err := in.Validate(fmap); err != nil {
		return err
	}

	gpuDriverKey := in.Key
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, gpuDriverKey.StreamKey(), cb)

	ignoreState := in.IgnoreState
	in.IgnoreState = false

	// Step-1: First commit to etcd
	changed := 0
	var gpuDriver edgeproto.GPUDriver
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		changed = 0
		if !s.store.STMGet(stm, &in.Key, &gpuDriver) {
			return in.Key.NotFoundError()
		}
		if err := isBusyState(&in.Key, gpuDriver.State, ignoreState); err != nil {
			return err
		}
		old := edgeproto.GPUDriver{}
		old.DeepCopyIn(&gpuDriver)
		changed = gpuDriver.CopyInFields(in)
		if err := gpuDriver.Validate(nil); err != nil {
			return err
		}
		if changed == 0 {
			return nil
		}
		// we'll only commit state change now,
		// obj update will happen as part of Step-3
		old.State = ChangeInProgress
		s.store.STMPut(stm, &old)
		return nil
	})
	if err != nil {
		return err
	}
	if changed == 0 {
		return nil
	}
	defer func() {
		if reterr != nil {
			s.undoStateChange(ctx, &in.Key)
		}
	}()

	sendObj, err := s.startGPUDriverStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopGPUDriverStream(ctx, cctx, &gpuDriverKey, sendObj, reterr, NoCleanupStream)
	}()

	// Step-2: Validate license-config
	if fmap.HasOrHasChild(edgeproto.GPUDriverFieldLicenseConfig) {
		if err := s.validateGPUDriverLicense(ctx, in); err != nil {
			return err
		}
		in.Fields = append(in.Fields, edgeproto.GPUDriverFieldLicenseConfigMd5Sum)
	}

	// Step-3: commit to etcd
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.GPUDriver{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		cur.CopyInFields(in)
		cur.State = ""
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	cb.Send(&edgeproto.Result{Message: "GPU driver updated successfully"})
	return nil
}

func isBusyState(key *edgeproto.GPUDriverKey, state string, ignoreState bool) error {
	if !ignoreState && state == ChangeInProgress {
		return fmt.Errorf("An action is already in progress for GPU driver %s", key.String())
	}
	return nil
}

func (s *GPUDriverApi) DeleteGPUDriver(in *edgeproto.GPUDriver, cb edgeproto.GPUDriverApi_DeleteGPUDriverServer) error {
	return s.deleteGPUDriverInternal(DefCallContext(), in, cb)
}

func (s *GPUDriverApi) deleteGPUDriverInternal(cctx *CallContext, in *edgeproto.GPUDriver, cb edgeproto.GPUDriverApi_DeleteGPUDriverServer) (reterr error) {
	ctx := cb.Context()
	if err := in.Key.ValidateKey(); err != nil {
		return err
	}
	gpuDriverKey := in.Key
	var err error
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, gpuDriverKey.StreamKey(), cb)

	ignoreState := in.IgnoreState
	in.IgnoreState = false

	// Step-1: First update state in etcd
	var gpuDriver edgeproto.GPUDriver
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &gpuDriver) {
			return in.Key.NotFoundError()
		}
		if gpuDriver.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		if !cctx.Undo {
			if err := isBusyState(&in.Key, gpuDriver.State, ignoreState); err != nil {
				return err
			}
		}
		gpuDriver.State = ChangeInProgress
		gpuDriver.DeletePrepare = true
		s.store.STMPut(stm, &gpuDriver)
		return nil
	})
	if err != nil {
		return err
	}
	defer func() {
		if reterr != nil {
			s.undoStateChange(ctx, &in.Key)
		}
	}()

	sendObj, err := s.startGPUDriverStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr == nil {
			// deletion is successful, cleanup stream
			cleanupStream = CleanupStream
		}
		s.stopGPUDriverStream(ctx, cctx, &gpuDriverKey, sendObj, reterr, cleanupStream)
	}()

	// Validate if driver is in use by Cloudlet
	inUse, cloudlets := s.all.cloudletApi.UsesGPUDriver(&in.Key)
	if inUse {
		return fmt.Errorf("GPU driver in use by Cloudlet(s): %s", strings.Join(cloudlets, ","))
	}

	// Step-2: And then delete obj from etcd
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		// delete GPU driver obj
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	if err != nil {
		return err
	}
	cb.Send(&edgeproto.Result{Message: "GPU driver deleted successfully"})
	return nil
}

func (s *GPUDriverApi) ShowGPUDriver(in *edgeproto.GPUDriver, cb edgeproto.GPUDriverApi_ShowGPUDriverServer) error {
	return s.cache.Show(in, func(obj *edgeproto.GPUDriver) error {
		copy := *obj
		for ii, _ := range copy.Builds {
			copy.Builds[ii].DriverPathCreds = ""
		}
		err := cb.Send(&copy)
		return err
	})
}

func (s *GPUDriverApi) AddGPUDriverBuild(in *edgeproto.GPUDriverBuildMember, cb edgeproto.GPUDriverApi_AddGPUDriverBuildServer) (reterr error) {
	cctx := DefCallContext()
	ctx := cb.Context()
	if err := in.Validate(); err != nil {
		return err
	}

	gpuDriverKey := in.Key
	var err error
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, gpuDriverKey.StreamKey(), cb)

	ignoreState := in.IgnoreState
	in.IgnoreState = false

	in.Build.DriverPathCreds = ""

	// Step-1: First commit to etcd
	var gpuDriver edgeproto.GPUDriver
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &gpuDriver) {
			return in.Key.NotFoundError()
		}
		if err := isBusyState(&in.Key, gpuDriver.State, ignoreState); err != nil {
			return err
		}
		for ii, _ := range gpuDriver.Builds {
			if gpuDriver.Builds[ii].Name == in.Build.Name {
				return fmt.Errorf("GPU driver build with same name already exists")
			}
		}
		gpuDriver.Builds = append(gpuDriver.Builds, in.Build)
		gpuDriver.State = ChangeInProgress
		s.store.STMPut(stm, &gpuDriver)
		return nil
	})
	if err != nil {
		return err
	}

	defer func() {
		if reterr != nil {
			// undo changes
			err = s.removeGPUDriverBuildInternal(DefCallContext().WithUndo(), in, cb)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to undo gpu driver build", "key", in.Key, "err", err)
			}
		}
	}()

	sendObj, err := s.startGPUDriverStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopGPUDriverStream(ctx, cctx, &gpuDriverKey, sendObj, reterr, NoCleanupStream)
	}()

	// pass driver path creds to download GPU driver package
	build := edgeproto.GPUDriverBuild{}
	build.DeepCopyIn(&in.Build)
	err = validateGPUDriver(ctx, &gpuDriver, &build, cb)
	if err != nil {
		return err
	}

	// Step-2: update it to etcd
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.GPUDriver{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		found := false
		for ii, _ := range cur.Builds {
			if cur.Builds[ii].Name == in.Build.Name {
				cur.Builds[ii] = in.Build
				found = true
				break
			}
		}
		if !found {
			cur.Builds = append(cur.Builds, in.Build)
		}
		cur.State = ""
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	cb.Send(&edgeproto.Result{Message: "GPU driver build added successfully"})
	return nil
}

func (s *GPUDriverApi) RemoveGPUDriverBuild(in *edgeproto.GPUDriverBuildMember, cb edgeproto.GPUDriverApi_RemoveGPUDriverBuildServer) error {
	return s.removeGPUDriverBuildInternal(DefCallContext(), in, cb)
}

func (s *GPUDriverApi) removeGPUDriverBuildInternal(cctx *CallContext, in *edgeproto.GPUDriverBuildMember, cb edgeproto.GPUDriverApi_RemoveGPUDriverBuildServer) (reterr error) {
	ctx := cb.Context()
	if err := in.Key.ValidateKey(); err != nil {
		return err
	}
	if err := in.Build.ValidateName(); err != nil {
		return err
	}

	ignoreState := in.IgnoreState
	in.IgnoreState = false

	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		var cur edgeproto.GPUDriver
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		if !cctx.Undo {
			if err := isBusyState(&in.Key, cur.State, ignoreState); err != nil {
				return err
			}
		}
		found := false
		for ii, build := range cur.Builds {
			if build.Name == in.Build.Name {
				cur.Builds = append(cur.Builds[:ii], cur.Builds[ii+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Unable to find GPU driver build %s", in.Build.Name)
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	cb.Send(&edgeproto.Result{Message: "GPU driver build removed successfully"})
	return nil
}

func (s *GPUDriverApi) GetGPUDriverBuildURL(ctx context.Context, in *edgeproto.GPUDriverBuildMember) (*edgeproto.GPUDriverBuildURL, error) {
	return &edgeproto.GPUDriverBuildURL{}, fmt.Errorf("Deprecated, user now manages build URL")
}

func (s *GPUDriverApi) GetGPUDriverLicenseConfig(ctx context.Context, key *edgeproto.GPUDriverKey) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, fmt.Errorf("Deprecated, user now manages license config URL")
}

// Copyright 2025 EdgeXR, Inc
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

package osmclient

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/restclient"
)

const (
	RESOURCE_STATE_READY = "READY"
)

func getOSMAppName(app *edgeproto.App) string {
	return NameSanitize(fmt.Sprintf("%s-%s%s", app.Key.Organization, app.Key.Name, app.Key.Version))
}

func getOSMAppDesc(app *edgeproto.App) string {
	// return a desc that can be used to track the state
	// of the app and if the OKA needs to be recreated.
	return fmt.Sprintf("%s.%s", app.ObjId, app.Revision)
}

func (s *OSMClient) CreateApp(ctx context.Context, app *edgeproto.App) (*OKAApp, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	name := getOSMAppName(app)
	desc := getOSMAppDesc(app)

	// check if already exists
	oka, err := s.GetApp(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup app %s, %s", name, err)
	}
	if oka != nil && oka.Description != desc {
		log.SpanLog(ctx, log.DebugLevelInfra, "create OKA app already exists but marker has changed, deleting and recreating", "name", name, "existing", oka.Description, "desired", desc)
		if err := s.DeleteApp(ctx, app); err != nil {
			return nil, fmt.Errorf("failed to delete old version of app %s [%s], %s", name, oka.Description, err)
		}
		oka = nil
	}
	if oka == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "create new OKA app", "name", name)
		// not found, create it now
		archive, err := createAppArchive(app)
		if err != nil {
			return nil, fmt.Errorf("failed to create App archive, %s", err)
		}

		mpfd := restclient.NewMultiPartFormData()
		mpfd.AddField("name", name)
		mpfd.AddField("profile_type", "app_profiles")
		mpfd.AddField("description", desc)
		mpfd.AddFileData("package", name+".tar.gz", "application/gzip", archive)

		buf := bytes.Buffer{}
		contentType, err := mpfd.Write(&buf)
		if err != nil {
			return nil, fmt.Errorf("failed to write multipart form-data, %s", err)
		}

		resp, err := client.AddOKAPackageWithBodyWithResponse(ctx, contentType, &buf)
		if err != nil {
			return nil, fmt.Errorf("failed to add OKA package for %s, %s", name, err)
		}
		if resp.StatusCode() != http.StatusCreated {
			return nil, fmt.Errorf("failed to add OKA pacakge for %s (%d), %s", name, resp.StatusCode(), string(resp.Body))
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "create OKA app already exists", "name", name)
	}
	return s.waitAppStatus(ctx, name, cloudcommon.Create)
}

func (s *OSMClient) DeleteApp(ctx context.Context, app *edgeproto.App) error {
	client, err := s.GetClient(ctx)
	if err != nil {
		return err
	}
	name := getOSMAppName(app)
	oka, err := s.GetApp(ctx, name)
	if err != nil {
		return err
	}
	if oka == nil {
		// no such app, we're done
		log.SpanLog(ctx, log.DebugLevelInfra, "delete OKA app not found", "name", name)
		return nil
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "deleting OKA app", "name", name)
	resp, err := client.DeleteOKAPackageWithResponse(ctx, oka.ID)
	if err != nil {
		return fmt.Errorf("failed to delete OKA app %s, %s", name, err)
	}
	if resp.StatusCode() != http.StatusAccepted {
		return fmt.Errorf("failed to delete OKA app %s (%d), %s", name, resp.StatusCode(), string(resp.Body))
	}
	// wait until app is gone
	_, err = s.waitAppStatus(ctx, name, cloudcommon.Delete)
	return err
}

func (s *OSMClient) waitAppStatus(ctx context.Context, name string, action cloudcommon.Action) (*OKAApp, error) {
	var retryDelay time.Duration
	if action == cloudcommon.Create {
		retryDelay = 12 * time.Second
	} else {
		retryDelay = 6 * time.Second
	}
	resState := "unknown"
	for ii := 0; ii < 100; ii++ {
		oka, err := s.GetApp(ctx, name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "check OKA app status failed", "name", name, "err", err)
			resState = err.Error()
		} else if oka == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "check OKA app status not found", "name", name)
			if action == cloudcommon.Delete {
				// desired final state for delete
				return nil, nil
			}
			resState = "not found"
		} else {
			// found
			log.SpanLog(ctx, log.DebugLevelInfra, "check OKA app status", "name", name, "resourceState", oka.ResourceState, "operatingState", oka.OperatingState)
			resState = oka.ResourceState
			if action == cloudcommon.Create && resState == RESOURCE_STATE_READY {
				// desired final state for create
				return oka, nil
			}
		}
		time.Sleep(retryDelay)
	}
	return nil, fmt.Errorf("timed out waiting for OKA app state, current state is: %s", resState)
}

// OpenAPI Spec is incomplete, it does not define return struct
// values for either LIST or GET OKA Apps.
// This struct is reverse engineered from actual response data.
type OKAApp struct {
	ID             string `json:"_id"`
	Name           string `json:"name"`
	ProfileType    string `json:"profile_type"`
	Description    string `json:"description"`
	ResourceState  string `json:"resourceState"`
	OperatingState string `json:"operatingState"`
}

func (s *OSMClient) GetApp(ctx context.Context, name string) (*OKAApp, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetOKAPackage(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body, %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response reading OKA apps (%d), %s", resp.StatusCode, string(out))
	}

	apps := []OKAApp{}
	err = json.Unmarshal(out, &apps)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OKA apps output, %s", err)
	}
	for _, app := range apps {
		if app.Name == name {
			return &app, nil
		}
	}
	return nil, nil
}

func createAppArchive(app *edgeproto.App) ([]byte, error) {
	// The tar.gz file should contain an archive of the following format:
	// manifests/app.yml
	// templates/app-ks.yml
	buf := bytes.Buffer{}
	gw := gzip.NewWriter(&buf)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	name := getOSMAppName(app)
	now := time.Now()

	// To deploy to a specific namespace, we can either
	// parameterize the manifest with "namespace: ${target_ns}"
	// and then add the target_ns to the postBuild section in
	// the kustomize.toolkit.fluxcd.io/v1 manifest,
	// or we can specify the targetNamespace parameter in the
	// kustomize.toolkit.fluxcd.io/v1 manifest.
	// We're doing the latter to avoid having to modify the
	// app manifest.
	mf := app.DeploymentManifest
	// write manifest dir
	manifestDir := tar.Header{
		Name:     "./manifests/",
		Mode:     0755,
		ModTime:  now,
		Typeflag: tar.TypeDir,
	}
	if err := tw.WriteHeader(&manifestDir); err != nil {
		return nil, fmt.Errorf("failed to write manifest directory %v, %s", manifestDir, err)
	}
	// write manifest
	manifestHdr := tar.Header{
		Name:     "./manifests/" + name + ".yml",
		Size:     int64(len(mf)),
		Mode:     0644,
		ModTime:  now,
		Typeflag: tar.TypeReg, // file
	}
	if err := tw.WriteHeader(&manifestHdr); err != nil {
		return nil, fmt.Errorf("failed to write manifest header %v, %s", manifestHdr, err)
	}
	num, err := tw.Write([]byte(mf))
	if err != nil {
		return nil, fmt.Errorf("failed to write manifest to archive, %s", err)
	}
	if num != len(mf) {
		return nil, fmt.Errorf("failed to write manifest, only wrote %d of %d bytes", num, len(mf))
	}

	// write template dir
	templateDir := tar.Header{
		Name:     "./templates/",
		Mode:     0755,
		ModTime:  now,
		Typeflag: tar.TypeDir,
	}
	if err := tw.WriteHeader(&templateDir); err != nil {
		return nil, fmt.Errorf("failed to write template directory %v, %s", templateDir, err)
	}
	// write template
	args := appTArgs{
		Name: name,
	}
	tempBuf := bytes.Buffer{}
	err = appT.Execute(&tempBuf, &args)
	if err != nil {
		return nil, fmt.Errorf("failed to execute app template, %s, %s", args, err)
	}
	dat := tempBuf.Bytes()
	templateHdr := tar.Header{
		Name:     "./templates/" + name + "-ks.yml",
		Size:     int64(len(dat)),
		Mode:     0644,
		ModTime:  now,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(&templateHdr); err != nil {
		return nil, fmt.Errorf("failed to write template header %v, %s", templateHdr, err)
	}
	num, err = tw.Write(dat)
	if err != nil {
		return nil, fmt.Errorf("failed to write template file to archive, %s", err)
	}
	if num != len(dat) {
		return nil, fmt.Errorf("failed to write template, only write %d of %d bytes", num, len(dat))
	}

	tw.Close()
	gw.Close()
	return buf.Bytes(), nil
}

type appTArgs struct {
	Name string
}

var appT = template.Must(template.New("appT").Parse(appTemplate))

var appTemplate = `apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: ${APPNAME}
  namespace: flux-system
spec:
  interval: 1h0m0s
  path: ./apps/{{ .Name }}/manifests
  prune: true
  targetNamespace: ${TARGET_NS}
  wait: true
  sourceRef:
    kind: GitRepository
    name: sw-catalogs
    namespace: flux-system
`

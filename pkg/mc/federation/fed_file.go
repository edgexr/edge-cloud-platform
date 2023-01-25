package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/labstack/echo/v4"
)

const (
	FileFieldFileId        = "fileId"
	FileFieldAppProviderId = "appProviderId"
	FileFieldFileName      = "fileName"
	FileFieldFileType      = "fileType"
	FileFieldRepoType      = "repoType"
	FileFieldImgOSType     = "imgOSType"
	FileFieldImgArchType   = "imgInsSetArch"
	FileFieldRepoLocation  = "fileRepoLocation"
	FileFieldFile          = "file"
	FileFieldChecksum      = "checksum"

	ImageStatusReady     = "Ready"
	ImageStatusSending   = "Sending"
	ImageStatusReceiving = "Receiving"
)

const (
	RepoTypePublic  = "PUBLICREPO"
	RepoTypePrivate = "PRIVATEREPO"
	RepoTypeUpload  = "UPLOAD"
)

const (
	HarborCredsAccount = "harbor"
)

func CheckFileType(fileType string) error {
	allowedVals := []string{}
	for _, typ := range fedewapi.AllowedVirtImageTypeEnumValues {
		if string(typ) == fileType {
			return nil
		}
		allowedVals = append(allowedVals, string(typ))
	}
	return fmt.Errorf("Image type %q not supported, must be one of %s", fileType, strings.Join(allowedVals, ", "))
}

func (p *PartnerApi) UploadFile(c echo.Context, fedCtxId FederationContextId) (reterr error) {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI UploadFile", "fedCtxId", fedCtxId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	req := c.Request()
	// 1 megabyte in memory storage, we don't allow inline data upload
	maxMemBytes := int64(1024 * 1024)
	req.ParseMultipartForm(maxMemBytes)

	image := ormapi.ProviderImage{}
	image.FederationName = provider.Name
	image.FileID = req.PostFormValue(FileFieldFileId)
	image.AppProviderId = req.PostFormValue(FileFieldAppProviderId)
	image.Name = req.PostFormValue(FileFieldFileName)
	image.Type = req.PostFormValue(FileFieldFileType)
	image.Checksum = req.PostFormValue(FileFieldChecksum)
	image.Status = ImageStatusReceiving
	repoType := req.PostFormValue(FileFieldRepoType)
	repoloc := req.PostFormValue(FileFieldRepoLocation)
	if image.FileID == "" {
		return fmt.Errorf("%s is missing", FileFieldFileId)
	}
	if image.AppProviderId == "" {
		return fmt.Errorf("%s is missing", FileFieldAppProviderId)
	}
	if image.Name == "" {
		return fmt.Errorf("%s is missing", FileFieldFileName)
	}
	if image.Type == "" {
		return fmt.Errorf("%s is missing", FileFieldFileType)
	}
	if err := CheckFileType(image.Type); err != nil {
		return err
	}
	_, _, err = req.FormFile(FileFieldFile)
	if err != nil && err != http.ErrMissingFile {
		return err
	}
	if err == nil {
		// TODO: handle inline uploads
		// This shouldn't accept Docker
		return fmt.Errorf("inline file upload not supported yet, use repolocation instead")
	}
	if repoloc == "" {
		return fmt.Errorf("%s must be specified, inline upload not supported", FileFieldRepoLocation)
	}
	src := &fedewapi.ObjectRepoLocation{}
	err = json.Unmarshal([]byte(repoloc), src)
	if err != nil {
		return fmt.Errorf("failed to json unmarshal repolocation: %s", err)
	}
	db := p.loggedDB(ctx)

	if src.RepoURL == nil {
		return fmt.Errorf("repoLocation's repo URL must be specified")
	}

	// We don't want to have to store and manage all kinds of
	// external image pull secrets, so if they are specified,
	// we copy the image in. If partner requests upload we honor it.
	if src.UserName == nil && src.Password == nil && src.Token == nil && repoType == RepoTypePublic {
		// keep as reference
		image.Status = ImageStatusReady
		image.Path = *src.RepoURL
		log.SpanLog(ctx, log.DebugLevelApi, "Saving image as reference", "info", image)
	} else {
		log.SpanLog(ctx, log.DebugLevelApi, "Will copy image")
		if src.UserName != nil && *src.UserName != "" {
			if src.Password == nil || *src.Password == "" {
				return fmt.Errorf("repolocation username specified but no password")
			}
		}
		if src.Password != nil && *src.Password != "" {
			if src.UserName == nil || *src.UserName == "" {
				return fmt.Errorf("repolocation password specified but no username")
			}
		}
	}

	err = db.Create(&image).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to save image, %s", err.Error()))
	}
	if image.Status == ImageStatusReady {
		// all done
		return nil
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := db.Delete(&image).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo image create", "image", image, "err", undoErr)
		}
	}()

	// Note that the provider Name is the owning org, and both
	// vm-registry and harbor can handle '/' in object names.
	localPath := fmt.Sprintf("%s/%s/%s", provider.Name, image.AppProviderId, image.Name)
	log.SpanLog(ctx, log.DebugLevelApi, "Federation retreiving upload file", "info", image, "local", localPath, "remoteurl", src.RepoURL)

	if image.Type == string(fedewapi.VIRTIMAGETYPE_QCOW2) || image.Type == string(fedewapi.VIRTIMAGETYPE_OVA) {
		log.SpanLog(ctx, log.DebugLevelApi, "download file into vm-registry", "info", image)
		// tell vm-registry to download it.
		// the pullspec contains the url to pull the image from,
		// plus any authentication needed.
		pullSpec := map[string]string{
			"url": *src.RepoURL,
		}
		if src.Token != nil {
			pullSpec["token"] = *src.Token
		}
		if src.UserName != nil {
			pullSpec["username"] = *src.UserName
		}
		if src.Password != nil {
			pullSpec["password"] = *src.Password
		}
		reqDat, err := json.Marshal(pullSpec)
		if err != nil {
			return err
		}

		auth, err := cloudcommon.GetRegistryAuth(ctx, p.vmRegistryAddr, cloudcommon.AllOrgs, p.vaultConfig)
		if err != nil {
			return err
		}

		localName := image.AppProviderId + "/" + image.Name
		apiPath := cloudcommon.GetArtifactPullPath(p.vmRegistryAddr, provider.Name, localName)
		image.Path = cloudcommon.GetArtifactStoragePath(p.vmRegistryAddr, provider.Name, localName)

		req, err := http.NewRequest(http.MethodPost, apiPath, strings.NewReader(string(reqDat)))
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelApi, "vm registry pull request", "url", apiPath)
		req.SetBasicAuth(auth.Username, auth.Password)
		req.Header.Set("Content-Type", "application/json")
		client := http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("Issuing pull request to vm-registry failed: %s", err)
		}
		defer resp.Body.Close()
		bd, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Issuing pull request to vm-registry failed: %d, %s", resp.StatusCode, string(bd))
		}
		out := ormapi.ArtifactObject{}
		err = json.Unmarshal(bd, &out)
		if err != nil {
			return fmt.Errorf("Upload succeeded but failed to parse pull response: %s", err)
		}
		log.SpanLog(ctx, log.DebugLevelApi, "uploaded vm-registry image", "out", out)
		// check that checksum matches
		if image.Checksum != "" && image.Checksum != out.MD5 {
			return fmt.Errorf("Upload succeeded but checksums mismatch, expected %s but is %s", image.Checksum, out.MD5)
		}
	} else if image.Type == string(fedewapi.VIRTIMAGETYPE_DOCKER) {
		log.SpanLog(ctx, log.DebugLevelApi, "copy docker file inot harbor", "info", image)
		// use skopeo to transfer docker image from source (remote)
		// to destination (local harbor)
		dest := fmt.Sprintf("%s/%s", util.TrimScheme(p.harborAddr), localPath)
		image.Path = dest

		args := []string{"copy", "-q"}
		if src.UserName != nil && src.Password != nil {
			args = append(args, "--src-creds", *src.UserName+":"+*src.Password)
		}

		auth, err := cloudcommon.GetAccountAuth(ctx, HarborCredsAccount, p.vaultConfig)
		if err != nil {
			return err
		}
		// set auth so that GetDockerImageChecksum uses it for basic auth
		auth.AuthType = cloudcommon.BasicAuth

		args = append(args, "--dest-creds",
			auth.Username+":"+auth.Password,
			"docker://"+strings.ToLower(*src.RepoURL),
			"docker://"+strings.ToLower(dest))
		cmd := exec.Command("skopeo", args...)
		logCmd := cmd.String()
		if src.Password != nil {
			logCmd = strings.ReplaceAll(logCmd, *src.Password, "***")
		}
		logCmd = strings.ReplaceAll(logCmd, auth.Password, "***")
		log.SpanLog(ctx, log.DebugLevelApi, "copy docker", "cmd", logCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "copy docker image failed", "src", src.RepoURL, "dest", dest, "out", string(out), "err", err)
			return fmt.Errorf("copy docker image failed: %s", string(out))
		}
		log.SpanLog(ctx, log.DebugLevelApi, "copied docker image", "out", string(out))
		if image.Checksum != "" {
			checksum, err := cloudcommon.GetDockerImageChecksum(ctx, image.Path, auth)
			if err != nil {
				return fmt.Errorf("Uploaded succeeded but failed to get checksum: %s", err)
			}
			if image.Checksum != checksum {
				return fmt.Errorf("Upload succeeded but checksums mismatch, expected %s but is %s", image.Checksum, checksum)
			}
		}
	} else {
		return fmt.Errorf("%s not supported yet", image.Type)
	}

	image.Status = ImageStatusReady
	err = db.Save(&image).Error
	if err != nil {
		// just log it, since it's just the status that we're missing
		log.SpanLog(ctx, log.DebugLevelApi, "failed to save image status", "image", image, "err", err)
	}
	return nil
}

func (p *PartnerApi) RemoveFile(c echo.Context, fedCtxId FederationContextId, fileId FileId) error {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI RemoveFile", "fedCtxId", fedCtxId, "fileId", fileId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	image := ormapi.ProviderImage{
		FederationName: provider.Name,
		FileID:         string(fileId),
	}
	db := p.loggedDB(ctx)
	res := db.Where(&image).First(&image)
	if res.RecordNotFound() {
		return fedError(http.StatusNotFound, fmt.Errorf("Specified file ID %s not found", string(fileId)))
	}
	if res.Error != nil {
		return fedError(http.StatusInternalServerError, res.Error)
	}

	if p.vmRegistryAddr != "" && strings.Contains(image.Path, p.vmRegistryAddr) {
		log.SpanLog(ctx, log.DebugLevelApi, "delete image from vm-registry", "image", image)
		// delete from vm-registry
		auth, err := cloudcommon.GetRegistryAuth(ctx, p.vmRegistryAddr, cloudcommon.AllOrgs, p.vaultConfig)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodDelete, image.Path, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(auth.Username, auth.Password)
		client := http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete local copy of image: %s", err))
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			bd, _ := io.ReadAll(resp.Body)
			return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete local copy of image: %d, %s", resp.StatusCode, string(bd)))
		}
	}
	if p.harborAddr != "" && strings.Contains(image.Path, util.TrimScheme(p.harborAddr)) {
		log.SpanLog(ctx, log.DebugLevelApi, "delete image from harbor", "image", image)
		auth, err := cloudcommon.GetAccountAuth(ctx, HarborCredsAccount, p.vaultConfig)
		if err != nil {
			return err
		}
		args := []string{"delete",
			"--creds", auth.Username + ":" + auth.Password,
			"docker://" + strings.ToLower(image.Path),
		}
		cmd := exec.Command("skopeo", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "delete docker image failed", "path", image.Path, "out", string(out), "err", err)
			return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete local copy of image: %s", string(out)))
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "deleting image", "image", image)
	err = db.Delete(&image).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete image: %s", err))
	}
	return nil
}

func (p *PartnerApi) ViewFile(c echo.Context, fedCtxId FederationContextId, fileId FileId) error {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI ViewFile", "fedCtxId", fedCtxId, "fileId", fileId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	image := ormapi.ProviderImage{
		FederationName: provider.Name,
		FileID:         string(fileId),
	}
	db := p.loggedDB(ctx)
	res := db.Where(&image).First(&image)
	if res.RecordNotFound() {
		return fedError(http.StatusNotFound, errors.New("Specified file ID not found"))
	}
	if res.Error != nil {
		return fedError(http.StatusInternalServerError, res.Error)
	}
	resp := fedewapi.ViewFile200Response{
		FileId:          image.FileID,
		AppProviderId:   image.AppProviderId,
		FileName:        image.Name,
		FileDescription: &image.Path,
		FileType:        fedewapi.VirtImageType(image.Type),
	}
	return c.JSON(http.StatusOK, resp)
}

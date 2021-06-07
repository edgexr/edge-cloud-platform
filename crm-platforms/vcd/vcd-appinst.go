package vcd

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

type VmAppOvfParams struct {
	ImageBaseFileName string
	DiskSizeInBytes   string
	OSType            string
}

var vcdDirectUser string = "vcdDirect"

var vmAppOvfTemplate = `<?xml version='1.0' encoding='UTF-8'?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References>
    <File ovf:id="file1" ovf:href="{{.ImageBaseFileName}}.vmdk"/>
  </References>
  <DiskSection>
    <Info>List of the virtual disks</Info>
    <Disk ovf:capacityAllocationUnits="byte" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:diskId="vmdisk1" ovf:capacity="{{.DiskSizeInBytes}}" ovf:fileRef="file1"/>
  </DiskSection>
  <VirtualSystem ovf:id="{{.ImageBaseFileName}}">
    <Info>A Virtual system</Info>
    <Name>{{.ImageBaseFileName}}</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="{{.OSType}}">
      <Info>The operating system installed</Info>
      <Description></Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
        <vmw:CoresPerSocket ovf:required="false">1</vmw:CoresPerSocket>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>4096MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 1</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogicsas</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="192"/>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SATA Controller</rasd:Description>
        <rasd:ElementName>SATA Controller 1</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.sata.ahci</rasd:ResourceSubType>
        <rasd:ResourceType>20</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="33"/>
      </Item>
      <Item>
      <rasd:Description>USB Controller (XHCI)</rasd:Description>
      <rasd:ElementName>USB controller</rasd:ElementName>
      <rasd:InstanceID>5</rasd:InstanceID>
      <rasd:ResourceSubType>vmware.usb.xhci</rasd:ResourceSubType>
      <rasd:ResourceType>23</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>CD/DVD Drive 1</rasd:ElementName>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceSubType>vmware.cdrom.remotepassthrough</rasd:ResourceSubType>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
      <Item ovf:required="false">
        <rasd:ElementName>Video card</rasd:ElementName>
        <rasd:InstanceID>8</rasd:InstanceID>
        <rasd:ResourceType>24</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="numDisplays" vmw:value="1"/>
        <vmw:Config ovf:required="false" vmw:key="graphicsMemorySizeInKB" vmw:value="262144"/>
        <vmw:Config ovf:required="false" vmw:key="use3dRenderer" vmw:value="automatic"/>
        <vmw:Config ovf:required="false" vmw:key="enable3DSupport" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="useAutoDetect" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="videoRamSizeInKB" vmw:value="4096"/>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="flags.vbsEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="cpuHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="nestedHVEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="virtualSMCPresent" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="flags.vvtdEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="cpuHotRemoveEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="memoryHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="bios"/>
      <vmw:Config ovf:required="false" vmw:key="virtualICH7MPresent" vmw:value="false"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
`

func (v *VcdPlatform) AddAppImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "app.ImagePath", app.ImagePath, "imageInfo", imageInfo, "flavor", flavor)

	artifactoryPathMinusFile := ""
	ovfFile := ""
	artifactoryHost := ""
	artifactoryOvfPath := ""

	u, err := url.Parse(app.ImagePath)
	if err != nil {
		return fmt.Errorf("unable to parse app image path - %v", err)
	}
	ps := strings.Split(u.Path, "/")
	if len(ps) == 0 {
		return fmt.Errorf("Unexpected appimage path")
	}
	artifactoryHost = u.Host
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	_, err = v.FindTemplate(ctx, imageInfo.LocalImageName, vcdClient)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Found existing image template: %s", imageInfo.LocalImageName))
		return nil
	}

	filesToCleanup := []string{}
	filesToUpload := []string{}

	defer func() {
		for _, file := range filesToCleanup {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file", "file", file)
			if delerr := infracommon.DeleteFile(file); delerr != nil {
				if !os.IsNotExist(delerr) {
					log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "file", file)
				}
			}
		}
	}()

	artifactoryOvfPath = strings.TrimSuffix(app.ImagePath, filepath.Ext(app.ImagePath)) + ".ovf"
	log.SpanLog(ctx, log.DebugLevelInfra, "Will generate OVF if not present", "artifactoryOvfPath", artifactoryOvfPath)
	_, _, err = infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, artifactoryOvfPath)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF already in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF not yet in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
		// need to download the qcow, convert to ovf/vmdk and then import to either VCD or Artifactory
		appFlavor, err := v.GetFlavor(ctx, flavor)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Downloading VM Image")
		fileWithPath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, app.ImagePath, imageInfo.Md5sum)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "fileWithPath", fileWithPath)

		// as the download may take a long time, refresh the session by triggering an API call
		_, err = v.GetOrg(ctx, vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to get org", "err", err)
			return fmt.Errorf("Failed to get VCD org")
		}
		filesToCleanup = append(filesToCleanup, fileWithPath)
		vmdkFile := fileWithPath
		if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
			updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
			vmdkFile, err = vmlayer.ConvertQcowToVmdk(ctx, fileWithPath, appFlavor.Disk)
			filesToCleanup = append(filesToCleanup, vmdkFile)
			if err != nil {
				return err
			}
			filesToUpload = append(filesToUpload, vmdkFile)
		}

		filenameNoExtension := strings.TrimSuffix(vmdkFile, filepath.Ext(vmdkFile))
		ovfFile = filenameNoExtension + ".ovf"

		imageFileBaseName := filepath.Base(filenameNoExtension)
		mappedOs, err := vmlayer.GetVmwareMappedOsType(app.VmAppOsType)
		if err != nil {
			return err
		}
		ovfParams := VmAppOvfParams{
			ImageBaseFileName: imageFileBaseName,
			DiskSizeInBytes:   fmt.Sprintf("%d", appFlavor.Disk*1024*1024*1024),
			OSType:            mappedOs,
		}
		ovfBuf, err := infracommon.ExecTemplate("vmwareOvf", vmAppOvfTemplate, ovfParams)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating OVF file", "ovfFile", ovfFile, "ovfParams", ovfParams)
		err = ioutil.WriteFile(ovfFile, ovfBuf.Bytes(), 0644)
		filesToCleanup = append(filesToCleanup, ovfFile)
		if err != nil {
			return fmt.Errorf("unable to write OVF file %s: %s", ovfFile, err.Error())
		}
		filesToUpload = append(filesToUpload, ovfFile)

		updateCallback(edgeproto.UpdateTask, "Uploading OVF to Artifactory")
		for _, f := range filesToUpload {
			artifactoryPathMinusFile = u.Scheme + "://" + u.Host + strings.Join(ps[:len(ps)-1], "/") + "/"
			uploadPath := artifactoryPathMinusFile + filepath.Base(f)
			log.SpanLog(ctx, log.DebugLevelInfra, "Uploading OVF to Artifactory", "uploadPath", uploadPath)
			file, err := os.Open(f)
			if err != nil {
				return fmt.Errorf("unable to open file: %s for upload - %v", f, err)
			}
			fi, err := file.Stat()
			if err != nil {
				return fmt.Errorf("Could not stat file: %s - %v", f, err)
			}
			reqConfig := cloudcommon.RequestConfig{}
			size := fi.Size()
			timeout := cloudcommon.GetTimeout(int(size))
			if timeout > 0 {
				reqConfig.Timeout = timeout
				reqConfig.ResponseHeaderTimeout = timeout
				log.SpanLog(ctx, log.DebugLevelApi, "increased upload timeout", "file", f, "timeout", timeout.String())
			}
			body := bufio.NewReader(file)
			reqConfig.Headers = make(map[string]string)
			reqConfig.Headers["Content-Type"] = "application/octet-stream"
			resp, err := cloudcommon.SendHTTPReq(ctx, "PUT", uploadPath, v.vmProperties.CommonPf.PlatformConfig.AccessApi, &reqConfig, body)
			log.SpanLog(ctx, log.DebugLevelInfra, "File uploaded", "file", file, "resp", resp, "err", err)
			file.Close()
			if err != nil {
				return fmt.Errorf("Error uploading %s to artifactory - %v", f, err)
			}
		}
	}
	// get a token that VCD can use to pull from the artifactory
	token, err := cloudcommon.GetAuthToken(ctx, artifactoryHost, v.vmProperties.CommonPf.PlatformConfig.AccessApi, vcdDirectUser)
	if err != nil {
		return fmt.Errorf("Fail to get artifactory token - %v", err)
	}
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed retrieving catalog", "cat", v.GetCatalogName())
		return fmt.Errorf("failed to find upload catalog - %v", err)
	}
	artifactoryOvfPathWithToken := strings.Replace(artifactoryOvfPath, artifactoryHost, vcdDirectUser+":"+token+"@"+artifactoryHost, 1)
	updateCallback(edgeproto.UpdateTask, "Importing OVF to VCD from Artifactory")
	err = v.ImportTemplateFromUrl(ctx, imageInfo.LocalImageName, artifactoryOvfPathWithToken, cat)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to upload from url, deleting", "err", err)
		delerr := v.DeleteTemplate(ctx, imageInfo.LocalImageName, vcdClient)
		if delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete failed", "delerr", delerr)
		}
		return err
	}
	return nil
}

func (v *VcdPlatform) DeleteImage(ctx context.Context, folder, image string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage", "image", image)
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	err := v.DeleteTemplate(ctx, image, vcdClient)
	if err != nil {
		if strings.Contains(err.Error(), govcd.ErrorEntityNotFound.Error()) {
			log.SpanLog(ctx, log.DebugLevelInfra, "image already deleted", "image", image)
			return nil
		} else {
			return fmt.Errorf("DeleteImage: %s failed - %v", image, err)
		}
	}
	return nil
}

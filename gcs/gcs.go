package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"cloud.google.com/go/storage"
	"github.com/mobiledgex/edge-cloud/vault"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func getOperatorReportsBucketName(deploymentTag string) string {
	return fmt.Sprintf("mobiledgex-%s-operator-reports", deploymentTag)
}

func GetVaultOperatorReportsPath(deploymentTag string) string {
	bucketName := getOperatorReportsBucketName(deploymentTag)
	return fmt.Sprintf("/secret/data/registry/%s", bucketName)
}

type GCSClient struct {
	Client     *storage.Client
	BucketName string
}

func NewClient(ctx context.Context, vaultConfig *vault.Config, deploymentTag string) (*GCSClient, error) {
	reportsPath := GetVaultOperatorReportsPath(deploymentTag)
	client, err := vaultConfig.Login()
	if err != nil {
		return nil, err
	}
	reportsData, err := vault.GetKV(client, reportsPath, 0)
	if err != nil {
		return nil, err
	}
	credsObj, err := json.Marshal(reportsData["data"])
	if err != nil {
		return nil, err
	}

	gcsClient := &GCSClient{}

	storageClient, err := storage.NewClient(ctx, option.WithCredentialsJSON(credsObj))
	if err != nil {
		panic(fmt.Errorf("storage.NewClient: %v", err))
	}

	gcsClient.Client = storageClient
	gcsClient.BucketName = getOperatorReportsBucketName(deploymentTag)
	return gcsClient, nil
}

func (gc *GCSClient) Close() {
	if gc != nil && gc.Client != nil {
		gc.Client.Close()
	}
}

func (gc *GCSClient) ListObjects(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	objs := []string{}
	it := gc.Client.Bucket(gc.BucketName).Objects(ctx, nil)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Bucket(%q).Objects: %v", gc.BucketName, err)
		}
		objs = append(objs, attrs.Name)
	}
	return objs, nil
}

// uploadFile uploads an object.
func (gc *GCSClient) UploadObject(ctx context.Context, objectName string, buf *bytes.Buffer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Upload an object with storage.Writer.
	wc := gc.Client.Bucket(gc.BucketName).Object(objectName).NewWriter(ctx)
	reader := bytes.NewReader(buf.Bytes())
	if _, err := io.Copy(wc, reader); err != nil {
		return fmt.Errorf("io.Copy: %v", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("Writer.Close: %v", err)
	}
	return nil
}

func (gc *GCSClient) DownloadObject(ctx context.Context, objectName string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	rc, err := gc.Client.Bucket(gc.BucketName).Object(objectName).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("GCS Object(%q) download error: %v", objectName, err)
	}
	defer rc.Close()

	data, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll: %v", err)
	}
	return data, nil
}

func (gc *GCSClient) DeleteObject(ctx context.Context, objectName string) error {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	o := gc.Client.Bucket(gc.BucketName).Object(objectName)
	if err := o.Delete(ctx); err != nil {
		return fmt.Errorf("GCS Object(%q) delete error: %v", objectName, err)
	}
	return nil
}

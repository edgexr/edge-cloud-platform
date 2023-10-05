package mccli

import (
	"bufio"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/ormctl"
	"github.com/spf13/cobra"
)

type ArtifactRequest struct {
	Org            string `json:"org,omitempty"`
	Path           string `json:"path,omitempty"`
	LocalFile      string `json:"localfile,omitempty"`
	RemoteUrl      string `json:"remoteurl,omitempty"`
	RemoteUsername string `json:"remoteusername,omitempty"`
	RemotePassword string `json:"remotepassword,omitempty"`
	RemoteToken    string `json:"remotetoken,omitempty"`
}

type ArtifactPullRequest struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

func (s *RootCommand) getArtifactCmdGroup() *cobra.Command {
	apiGroup := ormctl.MustGetGroup("Artifact")
	cmds := []*cli.Command{}
	for _, c := range apiGroup.Commands {
		c.ReqData = &ArtifactRequest{}
		cliCmd := s.ConvertCmd(c)
		switch c.Name {
		case "UploadArtifact":
			cliCmd.Run = s.uploadArtifact
		case "ShowArtifacts":
			cliCmd.Run = s.listArtifacts
		case "DownloadArtifact":
			cliCmd.Run = s.getArtifact
		case "DeleteArtifact":
			cliCmd.Run = s.deleteArtifact
		case "InfoArtifact":
			cliCmd.Run = s.infoArtifact
		case "UploadArtifactFromURL":
			cliCmd.Run = s.pullArtifact
		default:
			panic(fmt.Sprintf("getArtifactCmdGroup cmd %s not found", c.Name))
		}
		cmds = append(cmds, cliCmd)
	}
	return cli.GenGroup(strings.ToLower(apiGroup.Name), apiGroup.Desc, cmds)
}

func (s *RootCommand) uploadArtifact(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	art, _ := c.ReqData.(*ArtifactRequest)
	if art.Org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	if art.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if art.LocalFile == "" {
		return fmt.Errorf("local file cannot be empty")
	}

	fileInfo, err := os.Stat(art.LocalFile)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file %s not found", art.LocalFile)
	}

	file, err := os.Open(art.LocalFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// do a quick info check to see if we're authorized
	uri := s.buildArtifactPath(art)
	resp, err := s.client.HttpJsonSendReq("HEAD", uri, s.token, nil, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return bodyError(c, resp)
	}
	if resp.StatusCode == http.StatusOK {
		// check if local file matches remote file
		hash := md5.New()
		_, err := io.Copy(hash, file)
		if err != nil {
			return fmt.Errorf("Remote file %s/%s exists and failed to calculate md5 hash of local file %s: %s", art.Org, art.Path, art.LocalFile, err)
		}
		remoteMd5 := resp.Header.Get("X-Checksum-Md5")
		localMd5 := fmt.Sprintf("%x", hash.Sum(nil))
		if localMd5 == remoteMd5 {
			fmt.Printf("Remote file %s/%s exists and md5 hash matches local file %s\n", art.Org, art.Path, art.LocalFile)
			return nil
		}
		return fmt.Errorf("Remote file %s/%s already exists and hash (%s) does not match local (%s), please delete or move first", art.Org, art.Path, remoteMd5, localMd5)
	}

	bar := pb.Full.Start64(fileInfo.Size())
	defer bar.Finish()

	r, w := io.Pipe()
	mpart := multipart.NewWriter(w)
	copyDone := make(chan error, 1)
	barReader := bar.NewProxyReader(r)

	req, err := http.NewRequest("PUT", uri, barReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", mpart.FormDataContentType())

	go func() {
		defer w.Close()
		name := path.Base(art.LocalFile)
		part, err := mpart.CreateFormFile(name, name)
		if err != nil {
			copyDone <- err
			return
		}
		_, err = io.Copy(part, file)
		if err != nil {
			copyDone <- err
			return
		}
		err = mpart.Close()
		if err != nil {
			copyDone <- err
			return
		}
		copyDone <- nil
	}()

	client := http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	err = <-copyDone
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", http.StatusText(resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read json response: %v", err)
	}
	defer resp.Body.Close()
	out := ormapi.ArtifactObject{}
	err = json.Unmarshal(body, &out)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return check(c, resp.StatusCode, nil, &out)
}

func (s *RootCommand) pullArtifact(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	art, _ := c.ReqData.(*ArtifactRequest)
	if art.Org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	if art.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if art.RemoteUrl == "" {
		return fmt.Errorf("remote URL cannot be empty")
	}
	pullReq := ArtifactPullRequest{
		URL:      art.RemoteUrl,
		Username: art.RemoteUsername,
		Password: art.RemotePassword,
		Token:    art.RemoteToken,
	}
	uri := s.buildArtifactPullPath(art)
	if s.client.Debug {
		fmt.Printf("sending pull request to %s\n", uri)
	}
	resp, err := s.client.HttpJsonSendReq("POST", uri, s.token, &pullReq, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read error response: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pull request failed, %d: %s", resp.StatusCode, string(body))
	}
	out := ormapi.ArtifactObject{}
	err = json.Unmarshal(body, &out)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return check(c, resp.StatusCode, nil, &out)
}

func (s *RootCommand) listArtifacts(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	artifact, _ := c.ReqData.(*ArtifactRequest)
	// treat path as a simple filter
	pathFilter := artifact.Path
	artifact.Path = "" // ignore path in request
	uri := s.buildArtifactPath(artifact)
	queryParams := map[string]string{}
	if pathFilter != "" {
		queryParams["pathfilter"] = pathFilter
	}
	output := []ormapi.ArtifactObject{}
	st, _, err := s.client.HttpJsonSend("GET", uri, s.token, nil, &output, nil, queryParams, nil)
	return check(c, st, err, &output)
}

func (s *RootCommand) deleteArtifact(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	artifact, _ := c.ReqData.(*ArtifactRequest)
	if artifact.Org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	if artifact.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	uri := s.buildArtifactPath(artifact)
	resp, err := s.client.HttpJsonSendReq("DELETE", uri, s.token, nil, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return bodyError(c, resp)
	}
	fmt.Printf("Deleted %s\n", uri)
	return nil
}

func (s *RootCommand) getArtifact(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	artifact, _ := c.ReqData.(*ArtifactRequest)
	if artifact.Org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	if artifact.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// check for local file already exists
	localFile := artifact.LocalFile
	if localFile == "" {
		localFile = path.Base(artifact.Path)
	}
	if _, err := os.Stat(localFile); err == nil {
		return fmt.Errorf("local file %s already exists, aborting", localFile)
	}

	// do a quick info check to get size
	uri := s.buildArtifactPath(artifact)
	resp, err := s.client.HttpJsonSendReq("HEAD", uri, s.token, nil, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return bodyError(c, resp)
	}
	contentLength := resp.Header.Get("Content-Length")
	size, err := strconv.Atoi(contentLength)
	if err != nil {
		return fmt.Errorf("Failed to convert Content-Length of %s to number, %v", contentLength, err)
	}

	// open local file for write
	file, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// set up request
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	// set up progress bar
	bar := pb.Full.Start64(int64(size))
	defer bar.Finish()
	writer := bufio.NewWriter(file)
	barWriter := bar.NewProxyWriter(writer)

	// do request
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return bodyError(c, resp)
	}

	defer resp.Body.Close()
	io.Copy(barWriter, resp.Body)
	writer.Flush()
	return check(c, resp.StatusCode, nil, nil)
}

func (s *RootCommand) infoArtifact(c *cli.Command, args []string) error {
	_, err := s.runRestArgs(c, args)
	if err != nil {
		return err
	}
	artifact, _ := c.ReqData.(*ArtifactRequest)
	if artifact.Org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	if artifact.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	uri := s.buildArtifactPath(artifact)
	resp, err := s.client.HttpJsonSendReq("HEAD", uri, s.token, nil, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return bodyError(c, resp)
	}
	return check(c, resp.StatusCode, err, resp.Header)
}

func (s *RootCommand) buildArtifactPath(req *ArtifactRequest) string {
	prefix := ""
	if !strings.HasPrefix(s.addr, "http") {
		prefix = "http://"
	}
	return cloudcommon.GetArtifactStoragePath(prefix+s.addr, req.Org, req.Path)
}

func (s *RootCommand) buildArtifactPullPath(req *ArtifactRequest) string {
	prefix := ""
	if !strings.HasPrefix(s.addr, "http") {
		prefix = "http://"
	}
	return cloudcommon.GetArtifactPullPath(prefix+s.addr, req.Org, req.Path)
}

func bodyError(c *cli.Command, resp *http.Response) error {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read json response: %v", err)
	}
	message := strings.TrimSpace(string(body))
	err = fmt.Errorf("%s", message)
	return check(c, resp.StatusCode, err, nil)
}

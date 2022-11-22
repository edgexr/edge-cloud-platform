package mccli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/ormctl"
	"github.com/spf13/cobra"
)

type ArtifactRequest struct {
	Org       string `json:"org,omitempty"`
	Path      string `json:"path,omitempty"`
	LocalFile string `json:"localfile,omitempty"`
}

type ArtifactObject struct {
	Org       string    `json:"org,omitempty"`
	Path      string    `json:"path,omitempty"`
	Size      int64     `json:"size,omitempty"`
	CreatedBy string    `json:"createdby,omitempty"`
	Created   time.Time `json:"created,omitempty"`
	MimeType  string    `json:"mimeType,omitempty"`
	MD5       string    `json:"md5,omitempty"`
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
		case "ListArtifacts":
			cliCmd.Run = s.listArtifacts
		case "GetArtifact":
			cliCmd.Run = s.getArtifact
		case "DeleteArtifact":
			cliCmd.Run = s.deleteArtifact
		case "InfoArtifact":
			cliCmd.Run = s.infoArtifact
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

	// do a quick info check to see if we're authorized
	uri := s.buildArtifactPath(art)
	resp, err := s.client.HttpJsonSendReq("HEAD", uri, s.token, nil, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return bodyError(c, resp)
	}

	file, err := os.Open(art.LocalFile)
	if err != nil {
		return err
	}
	defer file.Close()

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
	out := ArtifactObject{}
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
	output := []ArtifactObject{}
	st, _, err := s.client.HttpJsonSend("GET", uri, s.token, nil, &output, nil, queryParams)
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

	uri := s.buildArtifactPath(artifact)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	localFile := artifact.LocalFile
	if localFile == "" {
		localFile = path.Base(artifact.Path)
	}

	file, err := os.Create(artifact.LocalFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	io.Copy(writer, resp.Body)
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
	uri := s.getArtifactUri() + "/artifacts"
	uri += "/" + req.Org
	if req.Path != "" {
		if req.Path[0] == '/' {
			uri += req.Path
		} else {
			uri += "/" + req.Path
		}
	}
	return uri
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

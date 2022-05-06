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

package e2esetup

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"

	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud/setup-env/util"
	"github.com/mobiledgex/yaml/v2"
)

type E2eServerName struct {
	Name string `json:"name"`
}

// The structure below is a full maildev email structure.
// However we only need some of the fields to check
type MailDevEmail struct {
	/*
		 * TODO - check html content in the future, once we know what the content of the email should look like
			HTML    string `json:"html"`
	*/
	Text    string `json:"text"`
	Headers struct {
		Subject string `json:"subject"`
		To      string `json:"to"`
		From    string `json:"from"`
		//		MessageID   string `json:"message-id"`
		//		Date        string `json:"date"`
		//		ContentType string `json:"content-type"`
		//		MimeVersion string `json:"mime-version"`
	} `json:"headers"`
	/*
	   * We don't care about anuthing other than data in the headers for now
	   	Subject   string `json:"subject"`
	   	MessageID string `json:"messageId"`
	   	Priority  string `json:"priority"`
	   	From      []struct {
	   		Address string `json:"address"`
	   		Name    string `json:"name"`
	   	} `json:"from"`
	   	To []struct {
	   		Address string `json:"address"`
	   		Name    string `json:"name"`
	   	} `json:"to"`
	   	Date     time.Time `json:"date"`
	   	ID       string    `json:"id"`
	   	Time     time.Time `json:"time"`
	   	Read     bool      `json:"read"`
	   	Envelope struct {
	   		From struct {
	   			Address string `json:"address"`
	   			Args    struct {
	   				BODY string `json:"BODY"`
	   			} `json:"args"`
	   		} `json:"from"`
	   		To []struct {
	   			Address string `json:"address"`
	   			Args    string `json:"args"`
	   		} `json:"to"`
	   		Host          string `json:"host"`
	   		RemoteAddress string `json:"remoteAddress"`
	   	} `json:"envelope"`
	   	Source string `json:"source"`
	*/
}

func GetMaildev(name string) *intprocess.Maildev {
	if name == "" {
		return Deployment.Maildevs[0]
	}
	for _, maildev := range Deployment.Maildevs {
		if maildev.Name == name {
			return maildev
		}
	}
	log.Fatalf("Error: could not find maildev container: %s\n", name)
	return nil
}

// get api
func RunEmailAPI(api, apiFile, outputDir string) error {
	servers := make([]E2eServerName, 0)
	if apiFile != "" {
		err := util.ReadYamlFile(apiFile, &servers)
		if err != nil {
			log.Printf("Unable to read api file: %s [%s]\n", apiFile, err.Error())
			return err
		}
	} else {
		servers = append(servers, E2eServerName{Name: ""})
	}

	switch api {
	case "check":
		for ii, sName := range servers {
			proc := GetMaildev(sName.Name)
			apiUrl := fmt.Sprintf("0.0.0.0:%d/email", proc.UiPort)
			cmd := exec.Command("curl", "-s", "-S", apiUrl)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("Error running show emails API on port %d, err: %v\n", proc.UiPort, err)
				return err
			}
			// unmarshal and marshal back to get just the fields we want
			emails := []MailDevEmail{}
			err = json.Unmarshal(out, &emails)
			if err != nil {
				log.Printf("email unmarshal error: %v\n", err)
				return err
			}
			cmpFilterEmailData(emails)
			// marshal back
			ymlOut, err := yaml.Marshal(&emails)
			if err != nil {
				log.Printf("email marshal into yaml error: %v\n", err)
				return err
			}
			if ii == 0 {
				util.PrintToFile("show-commands.yml", outputDir, util.PatchLicense(string(ymlOut)), true)
			} else {
				util.PrintToFile("show-commands.yml", outputDir, util.PatchLicense(string(ymlOut)), false)
			}
		}
	case "deleteall":
		for _, sName := range servers {
			proc := GetMaildev(sName.Name)
			apiUrl := fmt.Sprintf("0.0.0.0:%d/email/all", proc.UiPort)
			cmd := exec.Command("curl", "-s", "-S", "-X", "DELETE", apiUrl)
			_, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("err: %v\n", err)
				return err
			}
		}
	default:
		return fmt.Errorf("Unknown action for email subsystem")
	}
	return nil
}

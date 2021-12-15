package e2esetup

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
	"github.com/mobiledgex/yaml/v2"
)

const (
	ListSlackMessagesApi      = "/slack/listmessages"
	DeleteAllSlackMessagesApi = "/slack/deleteall"
	SlackWebhookApi           = "/slack/webhook"
)

// The structure below is a a partial slack webhook message
// that alertmanager sends to the slack endpoint
type TestSlackMsg struct {
	Channel     string `json:"channel"`
	Username    string `json:"username"`
	Attachments []struct {
		Title     string `json:"title"`
		TitleLink string `json:"title_link"`
		Text      string `json:"text"`
		Fallback  string `json:"fallback"`
	} `json:"attachments"`
}

func GetHttpServer(name string) *intprocess.HttpServer {
	if name == "" {
		return Deployment.HttpServers[0]
	}
	for _, server := range Deployment.HttpServers {
		if server.Name == name {
			return server
		}
	}
	log.Fatalf("Error: could not find http server process: %s\n", name)
	return nil
}

// get api
func RunSlackAPI(api, apiFile, outputDir string) error {
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
			proc := GetHttpServer(sName.Name)
			apiUrl := fmt.Sprintf("0.0.0.0:%d%s", proc.Port, ListSlackMessagesApi)
			cmd := exec.Command("curl", "-s", "-S", apiUrl)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("Error running show slack messages API on port %d, err: %v\n", proc.Port, err)
				return err
			}
			// unmarshal and marshal back to get just the fields we want
			msgs := []TestSlackMsg{}
			err = json.Unmarshal(out, &msgs)
			if err != nil {
				log.Printf("slack message unmarshal error: %v\n", err)
				return err
			}
			cmpFilterSlackData(msgs)
			// marshal back
			ymlOut, err := yaml.Marshal(&msgs)
			if err != nil {
				log.Printf("slack marshal into yaml error: %v\n", err)
				return err
			}
			if ii == 0 {
				util.PrintToFile("show-commands.yml", outputDir, string(ymlOut), true)
			} else {
				util.PrintToFile("show-commands.yml", outputDir, string(ymlOut), false)
			}
		}
	case "deleteall":
		for _, sName := range servers {
			proc := GetHttpServer(sName.Name)
			apiUrl := fmt.Sprintf("0.0.0.0:%d%s", proc.Port, DeleteAllSlackMessagesApi)
			cmd := exec.Command("curl", "-s", "-S", "-X", "DELETE", apiUrl)
			_, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("err: %v\n", err)
				return err
			}
		}
	default:
		return fmt.Errorf("Unknown action for mock slack subsystem")
	}
	return nil
}

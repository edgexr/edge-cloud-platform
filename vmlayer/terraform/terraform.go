package terraform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"strings"
	"sync"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var terraformLock sync.Mutex
var terraformRetryDelay = 10 * time.Second

type TerraformResources struct {
	Address   string                     `json:"address"`
	Values    map[string]json.RawMessage `json:"values"`
	Type      string                     `json:"type"`
	Name      string                     `json:"name"`
	DependsOn []string                   `json:"depends_on"`
}
type TerraformModule struct {
	Resources []TerraformResources `json:"resources"`
}
type TerraformValues struct {
	RootModule TerraformModule `json:"root_module"`
}
type TerraformStateData struct {
	Values TerraformValues `json:"values"`
}

func TimedTerraformCommand(ctx context.Context, dir string, name string, a ...string) (string, error) {

	terraformLock.Lock()
	defer terraformLock.Unlock()

	parmstr := strings.Join(a, " ")
	start := time.Now()
	log.SpanLog(ctx, log.DebugLevelInfra, "Terraform Command Start", "dir", dir, "name", name, "parms", parmstr)

	out, err := sh.NewSession().SetDir(dir).Command(name, a).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Terraform command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return string(out), err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Terraform Command Done", "parmstr", parmstr, "out", string(out), "elapsed time", time.Since(start))
	return string(out), nil
}

func DeleteTerraformPlan(ctx context.Context, terraformDir, planName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting Terraform Plan", "planName", planName)
	filename := terraformDir + "/" + planName + ".tf"
	if err := infracommon.DeleteFile(filename); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "delete terraform file failed", "filename", filename)
		//do the apply anyway minus the file
	}
	_, err := TimedTerraformCommand(ctx, terraformDir, "terraform", "apply", "--auto-approve")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "terraform apply for delete failed", "planName", planName, "err", err)
		return fmt.Errorf("terraform apply for delete failed: %v", err)
	}

	return nil
}

type TerraformOpts struct {
	cleanupOnFailure bool
	numRetries       int
	doInit           bool
}

type TerraformOp func(to *TerraformOpts) error

func WithCleanupOnFailure(val bool) TerraformOp {
	return func(t *TerraformOpts) error {
		t.cleanupOnFailure = val
		return nil
	}
}
func WithInit(val bool) TerraformOp {
	return func(t *TerraformOpts) error {
		t.doInit = val
		return nil
	}
}
func WithRetries(val int) TerraformOp {
	return func(t *TerraformOpts) error {
		t.numRetries = val
		return nil
	}
}

func CreateTerraformPlanFromTemplate(ctx context.Context, terraformDir string, templateData interface{}, planName string, templateString string, updateCallback edgeproto.CacheUpdateCallback, opts ...TerraformOp) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTerraformPlanFromTemplate", "planName", planName)
	var topts TerraformOpts
	updateCallback(edgeproto.UpdateTask, "Creating Terraform Plan for "+planName)
	for _, op := range opts {
		if err := op(&topts); err != nil {
			return "", err
		}
	}
	var buf bytes.Buffer

	tmpl, err := template.New(planName).Parse(templateString)
	if err != nil {
		// this is a bug
		log.WarnLog("template new failed", "templateString", templateString, "err", err)
		return "", fmt.Errorf("template new failed: %s", err)
	}
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		log.WarnLog("template execute failed", "templateData", templateData, "err", err)
		return "", fmt.Errorf("Template Execute Failed: %s", err)
	}

	unescaped := html.UnescapeString(buf.String())
	var unescapedBuf bytes.Buffer
	unescapedBuf.WriteString(unescaped)

	filename := terraformDir + "/" + planName + ".tf"
	log.SpanLog(ctx, log.DebugLevelInfra, "creating terraform file", "filename", filename)
	err = infracommon.WriteTemplateFile(filename, &unescapedBuf)
	if err != nil {
		return "", fmt.Errorf("WriteTemplateFile failed: %s", err)
	}
	if topts.doInit {
		log.SpanLog(ctx, log.DebugLevelInfra, "Doing terraform init", "planName", planName)
		_, err = TimedTerraformCommand(ctx, terraformDir, "terraform", "init")
		if err != nil {
			return "", err
		}

	}
	return filename, nil
}

func RunTerraformApply(ctx context.Context, terraformDir string, opts ...TerraformOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Running terraform apply")
	var topts TerraformOpts
	var err error
	for _, op := range opts {
		if err = op(&topts); err != nil {
			return err
		}
	}

	for i := 0; i <= topts.numRetries; i++ {
		log.SpanLog(ctx, log.DebugLevelInfra, "Doing terraform apply", "attempt", i, "max", topts.numRetries)
		_, err = TimedTerraformCommand(ctx, terraformDir, "terraform", "apply", "--auto-approve")
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Apply failed")
			if i < topts.numRetries {
				log.SpanLog(ctx, log.DebugLevelInfra, "Retry terraform apply after delay", "retry num", i+1, "max retries", topts.numRetries)
				time.Sleep(terraformRetryDelay)
			}
		} else {
			break
		}
	}
	return err
}

func ApplyTerraformPlan(ctx context.Context, terraformDir string, fileName string, updateCallback edgeproto.CacheUpdateCallback, opts ...TerraformOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ApplyTerraformPlan", "fileName", fileName)
	updateCallback(edgeproto.UpdateTask, "Applying Terraform Plan for "+fileName)
	var topts TerraformOpts
	for _, op := range opts {
		if err := op(&topts); err != nil {
			return err
		}
	}
	var err error
	log.SpanLog(ctx, log.DebugLevelInfra, "Doing terraform apply", "fileName", fileName)
	err = RunTerraformApply(ctx, terraformDir, opts...)

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Apply failed", "fileName", fileName)
		if topts.cleanupOnFailure {
			if delerr := infracommon.DeleteFile(fileName); delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "delete terraform file failed", "fileName", fileName)
			}
			// no re-apply without the current plan to remove
			err2 := RunTerraformApply(ctx, terraformDir)
			if err2 != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "terraform apply after delete failed", "fileName", fileName, "err", err)
			}

		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cleanup on failure set to no, not destroying", "fileName", fileName)
		}
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Terraform apply OK", "fileName", fileName)
	return nil
}

func GetTerraformState(ctx context.Context, dir string, data *TerraformStateData) error {
	out, err := TimedTerraformCommand(ctx, dir, "terraform", "show", "-json")
	if err != nil {
		return fmt.Errorf("terraform command failed: %v", err)
	}
	err = json.Unmarshal([]byte(out), &data)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal json terraform state data: %s -- %v", out, err)
	}
	return nil
}

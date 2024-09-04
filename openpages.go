package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/configuration/config_helpers"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/configuration/core_config"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/trace"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/ibmcloud"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/objectmanager"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/op_context"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/op_helpers"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/op_i18n"
	"github.ibm.com/OpenPages/grc-saas-cli/openpages/opmodel"
)

const cli_major_version = 0
const cli_miner_version = 0
const cli_build_version = 19

const cli_min_major_version = 0
const cli_min_miner_version = 0
const cli_min_build_version = 19

type OpenPagesPlugin struct {
}

type OpenPages struct {
	Name string `json:"Name"`
	GUID string `json:"GUID"`
}

func main() {
	opPlugin := new(OpenPagesPlugin)
	plugin.Start(opPlugin)
}

func (omPlugin *OpenPagesPlugin) DoBatchLoad(opContext *op_context.OpenPagesContext, srcDir string, srcFile string) {
	lines, err := op_helpers.ReadFileByLines(srcDir + "/" + srcFile)

	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on reading batch file {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
	err = objectmanager.DoLoad(opContext, srcDir, "load", lines)
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on process {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
}

func (omPlugin *OpenPagesPlugin) DoLoad(opContext *op_context.OpenPagesContext, srcDir string, srcFile string) {
	err := objectmanager.DoLoad(opContext, srcDir, "load", []string{srcFile})
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on process {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
}
func (omPlugin *OpenPagesPlugin) DoDump(opContext *op_context.OpenPagesContext, destDir string, outputFile string) {
	err := objectmanager.DoDump(opContext, destDir, outputFile)
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on process {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
}

func (omPlugin *OpenPagesPlugin) DoCreateTemplates(opContext *op_context.OpenPagesContext, destDir string) {
	err := objectmanager.DoCreateTemplates(opContext, destDir)
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on process {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
}

func (omPlugin *OpenPagesPlugin) DoValidate(opContext *op_context.OpenPagesContext, srcDir string, srcFile string) {
	err := objectmanager.DoLoad(opContext, srcDir, "validate", []string{srcFile})
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error on process {{.Err}}", map[string]interface{}{"Err": err.Error()}))
	}
}

func (omPlugin *OpenPagesPlugin) listOpenPagesGrid(opContext *op_context.OpenPagesContext, jsonformat bool) {
	list, err := ibmcloud.ListOpenPages(opContext)
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error occurred while fetching OpenPages list {{.Err}}", map[string]interface{}{"Err": err.Error()}))
		opContext.Logger.Printf(opContext.T("Error occurred while fetching OpenPages list {{.Err}}", map[string]interface{}{"Err": err.Error()}))
		return
	}
	if len(list) > 0 {
		var openpages []OpenPages
		table := opContext.Ui.Table([]string{"Name", "GUID"})
		for _, op := range list {
			table.Add(op.Name, op.Guid)
			openpages = append(openpages, OpenPages{
				Name: op.Name,
				GUID: op.Guid,
			})
		}
		if jsonformat {
			myJson, _ := json.MarshalIndent(openpages, "", "\t")
			fmt.Println(string(myJson))
		} else {
			table.Print()
			currentop := GetOpenPagesInstance(opContext)
			currentopfound := false
			if currentop != nil {
				for _, op := range list {
					if currentop.Guid == op.Guid {
						currentopfound = true
					}
				}
			}
			if currentop != nil && currentopfound {
				opContext.Info("Targeted OpenPages application[{{.Name}}] [{{.Guid}}]", map[string]interface{}{"Name": terminal.EntityNameColor(currentop.Name), "Guid": terminal.EntityNameColor(currentop.Guid)})
			}
			if !currentopfound {
				UnSetTragetOpenPagesInstance(opContext)
				opContext.Info("No OpenPages application Trageted")
			}
		}
	} else {
		if jsonformat {
			fmt.Println("[{\"message\":\"No OpenPages application found with the account\"}]")
		} else {
			opContext.Info("No OpenPages application found with the account")
		}

	}

}

func (omPlugin *OpenPagesPlugin) listOpenPages(opContext *op_context.OpenPagesContext, guid string, selectable bool) {
	list, err := ibmcloud.ListOpenPages(opContext)
	if err != nil {
		opContext.Ui.Failed(opContext.T("Error occurred while fetching OpenPages list {{.Err}}", map[string]interface{}{"Err": err.Error()}))
		opContext.Logger.Printf(opContext.T("Error occurred while fetching OpenPages list {{.Err}}", map[string]interface{}{"Err": err.Error()}))
		return
	}
	if len(list) > 0 {
		if selectable && guid != "" {
			for _, op := range list {
				if guid == op.Guid {
					SetOpenPagesInstance(op, opContext)
					opContext.Info("Targeted OpenPages application[{{.Name}}] [{{.Guid}}]", map[string]interface{}{"Name": terminal.EntityNameColor(op.Name), "Guid": terminal.EntityNameColor(op.Guid)})
					return
				}
			}
			opContext.Info("OpenPages application {{.Guid}} Not found", map[string]interface{}{"Guid": terminal.EntityNameColor(guid)})
		}
		if selectable {
			opContext.Info("Select an OpenPages application:")
		} else if !selectable {
			opContext.Info("OpenPages application:")
		}
		for index, op := range list {
			opContext.Ui.Info("%d. %s (%s)", index, op.Name, op.Guid)
		}

		if len(list) > 0 && selectable {
			var opindex int
			err = opContext.Ui.Prompt(opContext.T("Enter a number>"), &terminal.PromptOptions{HideInput: false}).Resolve(&opindex)
			if err != nil {
				panic(err)
			}
			SetOpenPagesInstance(list[opindex], opContext)
		}
		currentop := GetOpenPagesInstance(opContext)
		currentopfound := false
		if currentop != nil {
			for _, op := range list {
				if currentop.Guid == op.Guid {
					currentopfound = true
				}
			}
		}
		if currentop != nil && currentopfound {
			opContext.Info("Targeted OpenPages application[{{.Name}}] [{{.Guid}}]", map[string]interface{}{"Name": terminal.EntityNameColor(currentop.Name), "Guid": terminal.EntityNameColor(currentop.Guid)})
		}
		if !currentopfound {
			UnSetTragetOpenPagesInstance(opContext)
			opContext.Info("No OpenPages application Trageted")
		}

	} else {
		opContext.Info("No OpenPages application found with the account")
	}

}

func GetOpenPagesInstance(opContext *op_context.OpenPagesContext) *opmodel.Instances {

	data := op_helpers.ReadFile(config_helpers.PluginRepoCacheDir() + "/opinstances")
	if len(data) > 0 {
		var instance opmodel.Instances
		err := json.Unmarshal(data, &instance)
		if err == nil {
			opContext.Info("Error on Unmarshal configuration")
		}
		return &instance
	}
	return nil
}

func SetOpenPagesInstance(op opmodel.Instances, opContext *op_context.OpenPagesContext) {
	data, err := json.Marshal(op)
	if err == nil {
		err0 := op_helpers.CreateDirIfNotExists(config_helpers.PluginRepoCacheDir())
		if err0 == nil {
			opContext.Info("Error on set GUID")
		}
		err1 := op_helpers.WriteFile([]byte(string(data)), config_helpers.PluginRepoCacheDir()+"/opinstances")
		if err1 == nil {
			opContext.Info("Error on set GUID")
		}
	}
}

func UnSetTragetOpenPagesInstance(opContext *op_context.OpenPagesContext) {
	fmt.Sprintln(config_helpers.PluginRepoCacheDir())
	err := op_helpers.WriteFile([]byte(string("")), config_helpers.PluginRepoCacheDir()+"/opinstances")
	if err == nil {
		opContext.Info("Error on unset GUID")
	}
}

func GetOpBaseURL(prod bool, guid string, dashboardUrl string) string {
	if prod {
		if strings.Contains(dashboardUrl, "stg.openpages.ibm.com") {
			return fmt.Sprintf("https://%s.us-east-1.aws.stg.openpages.ibm.com", guid)
		} else {
			return fmt.Sprintf("https://%s.us-east-1.aws.openpages.ibm.com", guid)
		}
	} else {
		if strings.Contains(dashboardUrl, "dev.openpages.ibm.com") {
			return fmt.Sprintf("https://%s.us-east-1.aws.dev.openpages.ibm.com", guid)
		} else {
			return fmt.Sprintf("https://%s.us-east-1.aws.qa.openpages.ibm.com", guid)
		}
	}
}

func GetIBMCloudURL(prod bool) string {
	if prod {
		return "https://resource-controller.cloud.ibm.com/v2/resource_instances?type=service_instance&state=active"
	} else {
		return "https://resource-controller.test.cloud.ibm.com/v2/resource_instances?type=service_instance&state=active"
	}
}

func IsProd(iamUrl string) bool {
	return !strings.Contains(iamUrl, "test.cloud.ibm.com")
}

func (omPlugin *OpenPagesPlugin) Run(context plugin.PluginContext, args []string) {

	namespace := context.CommandNamespace()
	iamToken := context.IAMToken()
	prod := IsProd(context.IAMEndpoint())
	trace.Logger = trace.NewLogger(context.Trace())

	op_i18n.T = op_i18n.Init(context)

	InfoFunc := func(format string, args ...interface{}) {
		terminal.NewStdUI().Info(op_i18n.T(format, args...))
	}

	opContext := op_context.InitContext(terminal.NewStdUI(), trace.Logger, iamToken, GetIBMCloudURL(prod), "", &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}, op_i18n.T, InfoFunc)

	getToken := func() string { return op_helpers.GetIAMToken(context, opContext) }

	opContext.GetIamToken = getToken
	if iamToken == "" {
		opContext.Info("You are not logged in or expired. Log in by running {{.Cmd}}", map[string]interface{}{"Cmd": terminal.CommandColor("ibmcloud login")})
		return
	}

	if !op_helpers.CheckTokenValidity(opContext, strings.TrimPrefix(iamToken, "Bearer ")) {
		opContext.Info("You are not logged in or expired. Log in by running {{.Cmd}}", map[string]interface{}{"Cmd": terminal.CommandColor("ibmcloud login")})
		return
	}
	op_helpers.GetIAMToken(context, opContext)

	switch namespace {
	case "openpages":
		switch args[0] {
		case "list":
			{
				flg := len(args) == 3 && args[1] == "--output" && args[2] == "json"
				omPlugin.listOpenPagesGrid(opContext, flg)
			}
		case "select":
			{
				gid := ""
				if len(args) > 1 {
					gid = args[1]
				}
				omPlugin.listOpenPages(opContext, gid, true)
			}
		case "unselect":
			{
				UnSetTragetOpenPagesInstance(opContext)
			}
		}

	case "openpages om":

		op := GetOpenPagesInstance(opContext)
		if op == nil {
			opContext.Info("You are not selected an OpenPages instances. Select by running {{.Cmd}}", map[string]interface{}{"Cmd": terminal.CommandColor("ibmcloud openpages select")})
			return
		} else {
			opContext.Info("Selected OpenPages instances [{{.Name}}] [{{.Cmd}}]", map[string]interface{}{"Name": terminal.EntityNameColor(op.Name), "Cmd": terminal.EntityNameColor(op.Guid)})
		}
		//Setting Openpage Base URL based on the Openpages Instance selection.
		opContext.SetOpAppBaseUrl(GetOpBaseURL(prod, op.Guid, op.DashboardUrl))
		switch args[0] {
		case "load":
			argslen := len(args)
			if argslen != 3 {
				opContext.Info("Missing or invalid arguments.\nUsage: ibmcloud openpages om load <loader-file-path> <loader-file-prefix>")
				return
			}
			srcDir := args[1]
			scrFile := args[2]
			omPlugin.DoLoad(opContext, srcDir, scrFile)

		case "dump":
			argslen := len(args)
			if argslen != 3 {
				opContext.Info("Missing or invalid arguments.\nUsage: ibmcloud openpages om dump <loader-file-path> <loader-file-prefix>")
				return
			}
			destDir := args[1]
			outputFile := args[2]
			omPlugin.DoDump(opContext, destDir, outputFile)

		case "create-templates":
			argslen := len(args)
			if argslen != 2 {
				opContext.Info("Missing or invalid arguments.\n Usage: ibmcloud openpages om create-templates  <dump-dir>")
				return
			}
			destDir := args[1]
			omPlugin.DoCreateTemplates(opContext, destDir)

		case "validate":
			argslen := len(args)
			if argslen != 3 {
				opContext.Info("Missing or invalid arguments\n Usage: ibmcloud openpages om validate  <loader-file-path> <loader-file-prefix>")
				return
			}
			srcDir := args[1]
			scrFile := args[2]
			omPlugin.DoValidate(opContext, srcDir, scrFile)

		case "batch":
			argslen := len(args)
			if argslen != 3 {
				opContext.Info("Missing or invalid arguments\n Usage: ibmcloud openpages om batch  <batch-loader-dir> <batch-loader-list-file>")
				return
			}
			srcDir := args[1]
			scrFile := args[2]
			omPlugin.DoBatchLoad(opContext, srcDir, scrFile)
		default:

		}
	}

}

func (omPlugin *OpenPagesPlugin) GetMetadata() plugin.PluginMetadata {

	coreConfig := core_config.NewCoreConfig(
		func(err error) {
			panic("configuration error: " + err.Error())
		})

	T := op_i18n.InitWithLocale(coreConfig.Locale())

	return plugin.PluginMetadata{
		Name:    "openpages",
		Aliases: []string{"op"},
		Version: plugin.VersionType{
			Major: cli_major_version,
			Minor: cli_miner_version,
			Build: cli_build_version,
		},
		MinCliVersion: plugin.VersionType{
			Major: cli_min_major_version,
			Minor: cli_min_miner_version,
			Build: cli_min_build_version,
		},
		PrivateEndpointSupported: true,
		Namespaces: []plugin.Namespace{
			{
				Name:        "openpages",
				Aliases:     []string{"op"}, // namespace aliases,
				Description: T("Manage IBM OpenPages service configurations"),
			},
			{
				ParentName:  "openpages",
				Name:        "objectmanager",
				Aliases:     []string{"om"}, // namespace aliases
				Description: T("Run ObjectManager operations"),
			},
		},
		Commands: []plugin.Command{
			{
				Namespace:   "openpages",
				Name:        "list",
				Alias:       "ls",
				Description: T("List all OpenPages instances"),
				Usage:       "ibmcloud openpages list",
				Flags: []plugin.Flag{
					{
						Name:        "output json",
						Description: "Format output in JSON",
					},
				},
			},
			{
				Namespace:   "openpages",
				Name:        "select",
				Alias:       "s",
				Description: T("Select OpenPages instance for subsequent commands. Specify GUID of the service instance or select one from the prompted list."),
				Usage:       "ibmcloud openpages select [guid]",
			},
			{
				Namespace:   "openpages",
				Name:        "unselect",
				Alias:       "u",
				Description: T("Unselect OpenPages instance"),
				Usage:       "ibmcloud openpages unselect",
			},
			{
				Namespace:   "openpages om",
				Name:        "dump",
				Alias:       "d",
				Description: T("Dump OpenPages configuration by ObjectManager utility"),
				Usage:       "ibmcloud openpages om dump <loader-file-path> <loader-file-prefix> \n\t Example: ibmcloud openpages om dump exampledir examplefileprefix",
			},
			{
				Namespace:   "openpages om",
				Name:        "load",
				Alias:       "l",
				Description: T("Load OpenPages configuration by ObjectManager utility"),
				Usage:       "ibmcloud openpages om load <loader-file-path> <loader-file-prefix> \n\t Example: ibmcloud openpages om load exampledir examplefileprefix",
			},
			{
				Namespace:   "openpages om",
				Name:        "validate",
				Alias:       "v",
				Description: T("Validate OpenPages configuration loader file by ObjectManager utility"),
				Usage:       "ibmcloud openpages om validate  <loader-file-path> <loader-file-prefix> \n\t Example: ibmcloud openpages om validate exampledir examplefileprefix",
			},
			{
				Namespace:   "openpages om",
				Name:        "batch",
				Alias:       "b",
				Description: T("Load OpenPages configuration in batch mode by ObjectManager utility"),
				Usage:       "ibmcloud openpages om batch  <batch-loader-dir> <batch-loader-list-file> \n\t Example: ibmcloud openpages om batch exampledir examplefileprefix [ list of file name line by line]",
			},
			{
				Namespace:   "openpages om",
				Name:        "create-templates",
				Alias:       "c",
				Description: T("Provide initial content of ObjectManager.properties and ObjectManagerExportFilters.xml files to specified folder"),
				Usage:       "ibmcloud openpages om create-templates  <dump-dir> \n\t Example: ibmcloud openpages om c exampledir",
			},
		},
	}
}

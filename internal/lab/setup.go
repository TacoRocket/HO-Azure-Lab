package lab

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type AzureSetupConfig struct {
	InfraDir                      string
	OutputPath                    string
	HumanUserOutputPath           string
	Location                      string
	NamePrefix                    string
	SSHPublicKey                  string
	SSHPublicKeyFile              string
	CostProfile                   string
	AKSVMSize                     string
	EnableRoleTrustsCanary        bool
	EnableDeploymentHistoryCanary bool
	EnableDefaultFollowUps        bool
	EnableAzureML                 bool
	AzureMLWorkspaceName          string
	EnableDeploymentPathAddin     bool
	EnableResourceHijackingAddin  bool
	EnableExfilAddin              bool
	EnableComputeControlAddin     bool
	EnablePersistenceAddin        bool
	EnableHumanUserViewpoints     bool
	WriteOnly                     bool
	TofuBinary                    string
	AzureCLIBinary                string
	ProgressWriter                io.Writer
}

type followUpInfraStep struct {
	Name    string
	Targets []string
}

var defaultFollowUpInfrastructureSteps = []followUpInfraStep{
	{
		Name: "API Management",
		Targets: []string{
			"azurerm_api_management.main",
			"azurerm_api_management_named_value.backend_base",
			"azurerm_api_management_backend.public_api",
			"azurerm_api_management_api.public_api",
		},
	},
	{
		Name: "AKS",
		Targets: []string{
			"azurerm_kubernetes_cluster.main",
		},
	},
	{
		Name: "WAF/Application Gateway",
		Targets: []string{
			"azurerm_web_application_firewall_policy.application_gateway",
			"azurerm_application_gateway.edge",
		},
	},
}

func followUpInfrastructureSteps(config AzureSetupConfig) []followUpInfraStep {
	steps := []followUpInfraStep{}
	if shouldRunDefaultFollowUps(config) {
		steps = append(steps, defaultFollowUpInfrastructureSteps...)
	}
	if config.EnableAzureML {
		steps = append(steps, followUpInfraStep{
			Name: "Azure ML",
			Targets: []string{
				"azurerm_application_insights.azure_ml[0]",
				"azurerm_machine_learning_workspace.main[0]",
				"azurerm_machine_learning_compute_cluster.cpu[0]",
				"azurerm_machine_learning_datastore_blobstorage.lab_proof[0]",
			},
		})
	}
	if config.EnableDeploymentPathAddin {
		steps = append(steps, followUpInfraStep{
			Name: "Deployment Path Add-in",
			Targets: []string{
				"azurerm_automation_runbook.deployment_path[0]",
				"azurerm_automation_schedule.deployment_path[0]",
				"azurerm_automation_job_schedule.deployment_path[0]",
				"azurerm_automation_webhook.deployment_path[0]",
			},
		})
	}
	if config.EnableResourceHijackingAddin {
		steps = append(steps, followUpInfraStep{
			Name: "Resource Hijacking Add-in",
			Targets: []string{
				"azurerm_automation_runbook.resource_hijacking[0]",
				"azurerm_automation_schedule.resource_hijacking[0]",
				"azurerm_automation_job_schedule.resource_hijacking[0]",
				"azurerm_automation_webhook.resource_hijacking[0]",
			},
		})
	}
	if config.EnableExfilAddin {
		steps = append(steps, followUpInfraStep{
			Name: "Exfil Add-in",
			Targets: []string{
				"azurerm_eventhub_namespace.exfil[0]",
				"azurerm_eventhub.exfil_telemetry[0]",
				"azurerm_eventhub_consumer_group.exfil_review[0]",
				"azurerm_eventhub_namespace_authorization_rule.exfil_diagnostic_send[0]",
				"azurerm_monitor_diagnostic_setting.exfil_public_app_loganalytics[0]",
				"azurerm_monitor_diagnostic_setting.exfil_public_app_eventhub[0]",
				"azurerm_monitor_diagnostic_setting.exfil_public_app_storage[0]",
			},
		})
	}
	if config.EnableComputeControlAddin {
		steps = append(steps, followUpInfraStep{
			Name: "Compute Control Add-in",
			Targets: []string{
				"azurerm_linux_web_app.compute_control[0]",
			},
		})
	}
	if config.EnablePersistenceAddin {
		steps = append(steps, followUpInfraStep{
			Name: "Persistence Add-in",
			Targets: []string{
				"azurerm_logic_app_workflow.persistence[0]",
				"azurerm_logic_app_trigger_recurrence.persistence[0]",
				"azurerm_logic_app_action_http.persistence[0]",
				"azurerm_api_connection.queue[0]",
				"azurerm_logic_app_action_custom.persistence_queue_connector[0]",
				"azurerm_logic_app_workflow.no_identity[0]",
				"azurerm_logic_app_trigger_recurrence.no_identity[0]",
				"azurerm_logic_app_action_http.no_identity[0]",
			},
		})
	}
	return steps
}

func shouldRunDefaultFollowUps(config AzureSetupConfig) bool {
	if config.EnableDefaultFollowUps {
		return true
	}
	return strings.TrimSpace(config.CostProfile) == "default"
}

func coreExcludedInfrastructureSteps(activeFollowUpSteps []followUpInfraStep) []followUpInfraStep {
	steps := make([]followUpInfraStep, 0, len(defaultFollowUpInfrastructureSteps)+len(activeFollowUpSteps))
	seen := map[string]struct{}{}
	addStep := func(step followUpInfraStep) {
		if _, ok := seen[step.Name]; ok {
			return
		}
		seen[step.Name] = struct{}{}
		steps = append(steps, step)
	}
	for _, step := range defaultFollowUpInfrastructureSteps {
		addStep(step)
	}
	for _, step := range activeFollowUpSteps {
		addStep(step)
	}
	return steps
}

func DefaultGeneratedTFVarsPath(infraDir string) string {
	return filepath.Join(filepath.Dir(infraDir), ".generated", "azure.auto.tfvars.json")
}

func DefaultGeneratedHumanUsersPath(infraDir string) string {
	return filepath.Join(filepath.Dir(infraDir), ".generated", "human-viewpoints.json")
}

func DefaultGeneratedAzureMLWorkspaceNamePath(infraDir string) string {
	return filepath.Join(filepath.Dir(infraDir), ".generated", "azure-ml-workspace-name")
}

func BuildAzureSetupTFVars(config AzureSetupConfig) map[string]any {
	return map[string]any{
		"location":                         strings.TrimSpace(config.Location),
		"name_prefix":                      strings.TrimSpace(config.NamePrefix),
		"ssh_public_key":                   strings.TrimSpace(config.SSHPublicKey),
		"compute_profile":                  strings.TrimSpace(config.CostProfile),
		"aks_vm_size":                      strings.TrimSpace(config.AKSVMSize),
		"enable_role_trusts_canary":        config.EnableRoleTrustsCanary,
		"enable_deployment_history_canary": config.EnableDeploymentHistoryCanary,
		"enable_azure_ml":                  config.EnableAzureML,
		"azure_ml_workspace_name":          strings.TrimSpace(config.AzureMLWorkspaceName),
		"enable_deployment_path_addin":     config.EnableDeploymentPathAddin,
		"enable_resource_hijacking_addin":  config.EnableResourceHijackingAddin,
		"enable_exfil_addin":               config.EnableExfilAddin,
		"enable_compute_control_addin":     config.EnableComputeControlAddin,
		"enable_persistence_addin":         config.EnablePersistenceAddin,
	}
}

func RunAzureSetup(config AzureSetupConfig) (string, int, error) {
	infraDir := strings.TrimSpace(config.InfraDir)
	if infraDir == "" {
		return "", 0, fmt.Errorf("infra directory is required")
	}
	if strings.TrimSpace(config.Location) == "" {
		return "", 0, fmt.Errorf("location is required")
	}
	if strings.TrimSpace(config.NamePrefix) == "" {
		return "", 0, fmt.Errorf("name prefix is required")
	}
	if strings.TrimSpace(config.CostProfile) == "" {
		return "", 0, fmt.Errorf("cost profile is required")
	}
	if strings.TrimSpace(config.AKSVMSize) == "" {
		return "", 0, fmt.Errorf("AKS VM size is required")
	}

	progressWriter := config.ProgressWriter
	if progressWriter == nil {
		progressWriter = io.Discard
	}

	resolvedKey, err := resolveSSHPublicKey(config, progressWriter)
	if err != nil {
		return "", 0, err
	}
	config.SSHPublicKey = resolvedKey
	if config.EnableAzureML {
		workspaceName, err := resolveAzureMLWorkspaceName(config)
		if err != nil {
			return "", 0, err
		}
		config.AzureMLWorkspaceName = workspaceName
		fmt.Fprintf(progressWriter, "Using Azure ML workspace name %s\n", workspaceName)
	}

	outputPath := strings.TrimSpace(config.OutputPath)
	if outputPath == "" {
		outputPath = DefaultGeneratedTFVarsPath(infraDir)
	}
	if !filepath.IsAbs(outputPath) {
		absOutputPath, err := filepath.Abs(outputPath)
		if err != nil {
			return "", 0, fmt.Errorf("resolve tfvars output path %q: %w", outputPath, err)
		}
		outputPath = absOutputPath
	}
	if err := WriteJSON(outputPath, BuildAzureSetupTFVars(config)); err != nil {
		return "", 0, err
	}
	fmt.Fprintf(progressWriter, "Wrote Azure setup inputs to %s\n", outputPath)

	if config.WriteOnly {
		fmt.Fprintln(progressWriter, "Skipping OpenTofu apply because write-only mode was requested.")
		return outputPath, 0, nil
	}

	tofuBinary := strings.TrimSpace(config.TofuBinary)
	if tofuBinary == "" {
		tofuBinary = "tofu"
	}

	fmt.Fprintln(progressWriter, "Running OpenTofu init...")
	if err := runTofuCommand(progressWriter, infraDir, tofuBinary, "init", "-input=false"); err != nil {
		return outputPath, 1, err
	}

	activeFollowUpSteps := followUpInfrastructureSteps(config)

	fmt.Fprintln(progressWriter, "Running core OpenTofu apply...")
	applyErr := runTofuCommand(progressWriter, infraDir, tofuBinary, buildCoreApplyArgs(outputPath, coreExcludedInfrastructureSteps(activeFollowUpSteps))...)
	postApplyReady := applyErr == nil
	if applyErr != nil {
		if err := verifyCoreLabOutputs(infraDir, tofuBinary); err != nil {
			return outputPath, 1, applyErr
		}
		postApplyReady = true
		fmt.Fprintln(progressWriter, "WARNING: OpenTofu apply did not complete cleanly, but core lab outputs are available. Continuing best-effort post-apply steps.")
	}

	deploymentHistoryDir := filepath.Join(infraDir, "canaries", "deployment-history")
	var warnings []string
	if postApplyReady {
		for _, step := range activeFollowUpSteps {
			fmt.Fprintf(progressWriter, "Running follow-up OpenTofu apply for %s...\n", step.Name)
			if err := runTofuCommand(progressWriter, infraDir, tofuBinary, buildFollowUpApplyArgs(outputPath, step.Targets)...); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s follow-up infrastructure was not applied automatically: %v", step.Name, err))
			}
		}
	}
	if postApplyReady && config.EnableDeploymentHistoryCanary {
		azureBinary := strings.TrimSpace(config.AzureCLIBinary)
		if azureBinary == "" {
			azureBinary = "az"
		}
		fmt.Fprintln(progressWriter, "Creating deployment-history resource canaries...")
		if err := runDeploymentHistoryCanaries(progressWriter, infraDir, deploymentHistoryDir, tofuBinary, azureBinary, config.Location); err != nil {
			warnings = append(warnings, fmt.Sprintf("deployment-history resource canaries were not created automatically: %v", err))
		}
	}
	if postApplyReady && config.EnableHumanUserViewpoints {
		azureBinary := strings.TrimSpace(config.AzureCLIBinary)
		if azureBinary == "" {
			azureBinary = "az"
		}
		fmt.Fprintln(progressWriter, "Creating human-user viewpoints...")
		if err := runHumanUserViewpointSetup(progressWriter, config, tofuBinary, azureBinary); err != nil {
			warnings = append(warnings, fmt.Sprintf("human-user viewpoints were not created automatically: %v", err))
		}
	}

	for _, warning := range warnings {
		fmt.Fprintf(progressWriter, "WARNING: %s\n", warning)
	}
	if applyErr != nil {
		fmt.Fprintln(progressWriter, "Azure environment setup finished with warnings.")
		return outputPath, 1, nil
	}
	if len(warnings) > 0 {
		fmt.Fprintln(progressWriter, "Azure environment setup completed with warnings.")
		return outputPath, 0, nil
	}
	fmt.Fprintln(progressWriter, "Azure environment setup completed.")
	return outputPath, 0, nil
}

func resolveAzureMLWorkspaceName(config AzureSetupConfig) (string, error) {
	if name := strings.TrimSpace(config.AzureMLWorkspaceName); name != "" {
		return name, nil
	}
	path := DefaultGeneratedAzureMLWorkspaceNamePath(config.InfraDir)
	if data, err := os.ReadFile(path); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			return name, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read Azure ML workspace name from %s: %w", path, err)
	}
	suffix, err := randomFromAlphabet(8, "abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return "", err
	}
	name := "aml2-ops-" + suffix
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create Azure ML workspace name directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(name+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write Azure ML workspace name to %s: %w", path, err)
	}
	return name, nil
}

func runTofuCommand(progressWriter io.Writer, workingDir, tofuBinary string, args ...string) error {
	cmd := exec.Command(tofuBinary, args...)
	cmd.Dir = workingDir
	stdout := newTofuProgressWriter(progressWriter)
	cmd.Stdout = stdout
	cmd.Stderr = progressWriter
	cmd.Env = os.Environ()
	err := cmd.Run()
	_ = stdout.Flush()
	return err
}

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

type tofuProgressWriter struct {
	dst       io.Writer
	line      bytes.Buffer
	total     int
	started   int
	completed int
	seenStart map[string]struct{}
	seenDone  map[string]struct{}
}

func newTofuProgressWriter(dst io.Writer) *tofuProgressWriter {
	if dst == nil {
		dst = io.Discard
	}
	return &tofuProgressWriter{
		dst:       dst,
		seenStart: map[string]struct{}{},
		seenDone:  map[string]struct{}{},
	}
}

func (w *tofuProgressWriter) Write(data []byte) (int, error) {
	if _, err := w.dst.Write(data); err != nil {
		return 0, err
	}
	for _, b := range data {
		w.line.WriteByte(b)
		if b == '\n' {
			w.processLine(w.line.String())
			w.line.Reset()
		}
	}
	return len(data), nil
}

func (w *tofuProgressWriter) Flush() error {
	if w.line.Len() == 0 {
		return nil
	}
	w.processLine(w.line.String())
	w.line.Reset()
	return nil
}

func (w *tofuProgressWriter) processLine(line string) {
	clean := strings.TrimSpace(ansiEscapePattern.ReplaceAllString(line, ""))
	if clean == "" {
		return
	}
	if total, ok := plannedCreateCount(clean); ok {
		w.total = total
		fmt.Fprintf(w.dst, "OpenTofu rollout plan: %d resource(s) to create.\n", total)
		return
	}
	if resource, ok := tofuResourceStatus(clean, "Creating..."); ok {
		if _, seen := w.seenStart[resource]; seen {
			return
		}
		w.seenStart[resource] = struct{}{}
		w.started++
		fmt.Fprintf(w.dst, "OpenTofu rollout start %s: %s\n", w.progressLabel(w.started), resource)
		return
	}
	if resource, ok := tofuResourceStatus(clean, "Creation complete"); ok {
		if _, seen := w.seenDone[resource]; seen {
			return
		}
		w.seenDone[resource] = struct{}{}
		w.completed++
		fmt.Fprintf(w.dst, "OpenTofu rollout complete %s: %s\n", w.progressLabel(w.completed), resource)
	}
}

func (w *tofuProgressWriter) progressLabel(current int) string {
	if w.total > 0 {
		return fmt.Sprintf("%d/%d", current, w.total)
	}
	return fmt.Sprintf("%d/?", current)
}

func plannedCreateCount(line string) (int, bool) {
	const prefix = "Plan: "
	start := strings.Index(line, prefix)
	if start == -1 {
		return 0, false
	}
	rest := line[start+len(prefix):]
	end := strings.Index(rest, " to add")
	if end == -1 {
		return 0, false
	}
	total, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		return 0, false
	}
	return total, true
}

func tofuResourceStatus(line, marker string) (string, bool) {
	if !strings.Contains(line, marker) {
		return "", false
	}
	colon := strings.Index(line, ":")
	if colon == -1 {
		return "", false
	}
	resource := strings.TrimSpace(line[:colon])
	return resource, resource != ""
}

func buildCoreApplyArgs(outputPath string, followUpSteps []followUpInfraStep) []string {
	args := []string{
		"apply",
		"-input=false",
		"-auto-approve",
		"-var-file",
		outputPath,
	}
	for _, step := range followUpSteps {
		for _, target := range step.Targets {
			args = append(args, "-exclude="+target)
		}
	}
	return args
}

func buildFollowUpApplyArgs(outputPath string, targets []string) []string {
	args := []string{
		"apply",
		"-input=false",
		"-auto-approve",
		"-var-file",
		outputPath,
	}
	for _, target := range targets {
		args = append(args, "-target="+target)
	}
	return args
}

type tofuOutputEntry struct {
	Value any `json:"value"`
}

func loadTofuOutputs(workingDir, tofuBinary string) (map[string]tofuOutputEntry, error) {
	cmd := exec.Command(tofuBinary, "output", "-json")
	cmd.Dir = workingDir
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tofu output -json failed: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	entries := map[string]tofuOutputEntry{}
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, fmt.Errorf("parse tofu output JSON: %w", err)
	}
	return entries, nil
}

func verifyCoreLabOutputs(workingDir, tofuBinary string) error {
	entries, err := loadTofuOutputs(workingDir, tofuBinary)
	if err != nil {
		return err
	}
	if _, err := outputString(entries, "subscription_id"); err != nil {
		return err
	}
	if _, err := outputStringMap(entries, "resource_group_names"); err != nil {
		return err
	}
	return nil
}

type humanUserViewpointRecord struct {
	Viewpoint         string `json:"viewpoint"`
	DisplayName       string `json:"display_name"`
	MailNickname      string `json:"mail_nickname"`
	UserPrincipalName string `json:"user_principal_name"`
	Password          string `json:"password"`
	ObjectID          string `json:"object_id"`
	RoleName          string `json:"role_name"`
	Scope             string `json:"scope"`
	LoginReady        bool   `json:"login_ready"`
	LoginCheckError   string `json:"login_check_error,omitempty"`
}

type humanUserViewpointOutput struct {
	Domain string                              `json:"domain"`
	Users  map[string]humanUserViewpointRecord `json:"users"`
}

type graphOrganizationResponse struct {
	Value []struct {
		VerifiedDomains []struct {
			Name      string `json:"name"`
			IsDefault bool   `json:"isDefault"`
			IsInitial bool   `json:"isInitial"`
		} `json:"verifiedDomains"`
	} `json:"value"`
}

type azureADUserResponse struct {
	ID string `json:"id"`
}

func runHumanUserViewpointSetup(progressWriter io.Writer, config AzureSetupConfig, tofuBinary, azureBinary string) error {
	outputs, err := loadTofuOutputs(config.InfraDir, tofuBinary)
	if err != nil {
		return err
	}
	subscriptionID, err := outputString(outputs, "subscription_id")
	if err != nil {
		return err
	}
	resourceGroups, err := outputStringMap(outputs, "resource_group_names")
	if err != nil {
		return err
	}
	domain, err := discoverTenantDefaultDomain(azureBinary, config.InfraDir)
	if err != nil {
		return err
	}

	suffix, err := randomDigits(12)
	if err != nil {
		return err
	}

	users := []struct {
		key         string
		displayName string
		nickname    string
		roleName    string
		scope       string
	}{
		{
			key:         "dev_user",
			displayName: "HOdev" + suffix,
			nickname:    "hodev" + suffix,
			roleName:    "Contributor",
			scope:       fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroups["workload"]),
		},
		{
			key:         "business_user",
			displayName: "HOuser" + suffix,
			nickname:    "houser" + suffix,
			roleName:    "Reader",
			scope:       fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroups["workload"]),
		},
	}

	result := humanUserViewpointOutput{
		Domain: domain,
		Users:  map[string]humanUserViewpointRecord{},
	}
	var loginWarnings []string
	for _, user := range users {
		password, err := randomPassword(30)
		if err != nil {
			return err
		}
		upn := fmt.Sprintf("%s@%s", user.nickname, domain)
		objectID, err := createAzureADUser(azureBinary, config.InfraDir, user.displayName, user.nickname, upn, password)
		if err != nil {
			return err
		}
		if err := createAzureRoleAssignment(azureBinary, config.InfraDir, objectID, user.roleName, user.scope); err != nil {
			return err
		}
		record := humanUserViewpointRecord{
			Viewpoint:         user.key,
			DisplayName:       user.displayName,
			MailNickname:      user.nickname,
			UserPrincipalName: upn,
			Password:          password,
			ObjectID:          objectID,
			RoleName:          user.roleName,
			Scope:             user.scope,
		}
		if err := validateAzureUserLogin(azureBinary, upn, password); err != nil {
			record.LoginReady = false
			record.LoginCheckError = err.Error()
			loginWarnings = append(loginWarnings, fmt.Sprintf("%s login smoke check failed: %v", upn, err))
		} else {
			record.LoginReady = true
		}
		result.Users[user.key] = record
	}

	outputPath := strings.TrimSpace(config.HumanUserOutputPath)
	if outputPath == "" {
		outputPath = DefaultGeneratedHumanUsersPath(config.InfraDir)
	}
	if err := WriteJSON(outputPath, result); err != nil {
		return err
	}
	fmt.Fprintf(progressWriter, "Human-user viewpoints created and recorded at %s\n", outputPath)
	if len(loginWarnings) > 0 {
		return errors.New(strings.Join(loginWarnings, "; "))
	}
	return nil
}

func discoverTenantDefaultDomain(azureBinary, workingDir string) (string, error) {
	output, err := runAzureCommand(
		azureBinary,
		workingDir,
		"rest",
		"--method", "get",
		"--url", "https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains",
		"--only-show-errors",
		"--output", "json",
	)
	if err != nil {
		return "", fmt.Errorf("query tenant verified domains: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	var response graphOrganizationResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return "", fmt.Errorf("parse tenant verified domains: %w", err)
	}
	if len(response.Value) == 0 {
		return "", fmt.Errorf("tenant organization response did not contain any organization entries")
	}
	var fallback string
	for _, domain := range response.Value[0].VerifiedDomains {
		if strings.TrimSpace(domain.Name) == "" {
			continue
		}
		if fallback == "" {
			fallback = domain.Name
		}
		if domain.IsDefault || domain.IsInitial {
			return domain.Name, nil
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("tenant organization response did not include any usable verified domain names")
	}
	return fallback, nil
}

func createAzureADUser(azureBinary, workingDir, displayName, nickname, upn, password string) (string, error) {
	output, err := runAzureCommand(
		azureBinary,
		workingDir,
		"ad", "user", "create",
		"--display-name", displayName,
		"--password", password,
		"--user-principal-name", upn,
		"--mail-nickname", nickname,
		"--force-change-password-next-sign-in", "false",
		"--only-show-errors",
		"--output", "json",
	)
	if err != nil {
		return "", fmt.Errorf("create user %q: %w\n%s", upn, err, strings.TrimSpace(string(output)))
	}
	var response azureADUserResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return "", fmt.Errorf("parse user create response for %q: %w", upn, err)
	}
	if strings.TrimSpace(response.ID) == "" {
		return "", fmt.Errorf("user create response for %q did not include an object id", upn)
	}
	return response.ID, nil
}

func createAzureRoleAssignment(azureBinary, workingDir, objectID, roleName, scope string) error {
	output, err := runAzureCommand(
		azureBinary,
		workingDir,
		"role", "assignment", "create",
		"--assignee-object-id", objectID,
		"--assignee-principal-type", "User",
		"--role", roleName,
		"--scope", scope,
		"--only-show-errors",
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("create %s role assignment for %q: %w\n%s", roleName, objectID, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateAzureUserLogin(azureBinary, upn, password string) error {
	configDir, err := os.MkdirTemp("/tmp", "ho-azure-human-login-")
	if err != nil {
		return fmt.Errorf("create temporary Azure config directory: %w", err)
	}
	defer os.RemoveAll(configDir)

	loginCmd := exec.Command(
		azureBinary,
		"login",
		"--username", upn,
		"--password", password,
		"--output", "none",
		"--only-show-errors",
	)
	loginCmd.Env = envWithOverrides("AZURE_CONFIG_DIR=" + configDir)
	output, err := loginCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(output)))
	}

	accountCmd := exec.Command(azureBinary, "account", "show", "--output", "none", "--only-show-errors")
	accountCmd.Env = envWithOverrides("AZURE_CONFIG_DIR=" + configDir)
	output, err = accountCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("az account show after login failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func randomDigits(length int) (string, error) {
	return randomFromAlphabet(length, "0123456789")
}

func randomPassword(length int) (string, error) {
	return randomFromAlphabet(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+")
}

func randomFromAlphabet(length int, alphabet string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("random string length must be positive")
	}
	if alphabet == "" {
		return "", fmt.Errorf("random string alphabet is required")
	}
	bytes := make([]byte, length)
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, value := range buf {
		bytes[i] = alphabet[int(value)%len(alphabet)]
	}
	return string(bytes), nil
}

func outputString(entries map[string]tofuOutputEntry, key string) (string, error) {
	raw, ok := entries[key]
	if !ok {
		return "", fmt.Errorf("missing tofu output %q", key)
	}
	value, ok := raw.Value.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("tofu output %q was not a non-empty string", key)
	}
	return value, nil
}

func outputStringMap(entries map[string]tofuOutputEntry, key string) (map[string]string, error) {
	raw, ok := entries[key]
	if !ok {
		return nil, fmt.Errorf("missing tofu output %q", key)
	}
	valueMap, ok := raw.Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tofu output %q was not an object", key)
	}
	result := map[string]string{}
	for name, value := range valueMap {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("tofu output %q field %q was not a non-empty string", key, name)
		}
		result[name] = text
	}
	return result, nil
}

func outputNestedString(entries map[string]tofuOutputEntry, key, field string) (string, error) {
	raw, ok := entries[key]
	if !ok {
		return "", fmt.Errorf("missing tofu output %q", key)
	}
	valueMap, ok := raw.Value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("tofu output %q was not an object", key)
	}
	value, ok := valueMap[field].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("tofu output %q field %q was not a non-empty string", key, field)
	}
	return value, nil
}

func runAzureCommand(binary, workingDir string, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.Dir = workingDir
	cmd.Env = os.Environ()
	return cmd.CombinedOutput()
}

func runAzureJSONCommand(binary, workingDir string, payload any, args ...string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal Azure request body: %w", err)
	}
	argsWithBody := append(args, "--body", string(body))
	output, err := runAzureCommand(binary, workingDir, argsWithBody...)
	if err != nil {
		return fmt.Errorf("az command failed: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForDeploymentState(azureBinary, workingDir, uriPath string, allowedStates []string) (string, error) {
	allowed := map[string]bool{}
	for _, state := range allowedStates {
		allowed[state] = true
	}
	lastState := ""
	for attempt := 0; attempt < 10; attempt++ {
		output, err := runAzureCommand(
			azureBinary,
			workingDir,
			"rest",
			"--method", "get",
			"--uri", fmt.Sprintf("https://management.azure.com%s?api-version=2022-09-01", uriPath),
			"--query", "properties.provisioningState",
			"--output", "tsv",
		)
		if err == nil {
			lastState = strings.TrimSpace(string(output))
			if allowed[lastState] {
				return lastState, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return lastState, fmt.Errorf("deployment %s did not reach one of %v; last state was %q", uriPath, allowedStates, lastState)
}

func runDeploymentHistoryCanaries(progressWriter io.Writer, infraDir, deploymentHistoryDir, tofuBinary, azureBinary, location string) error {
	outputs, err := loadTofuOutputs(infraDir, tofuBinary)
	if err != nil {
		return err
	}

	subscriptionID, err := outputString(outputs, "subscription_id")
	if err != nil {
		return err
	}
	resourceGroups, err := outputStringMap(outputs, "resource_group_names")
	if err != nil {
		return err
	}
	subscriptionDeploymentName, err := outputNestedString(outputs, "deployment_history", "subscription_deployment_name")
	if err != nil {
		return err
	}
	resourceGroupDeploymentName, err := outputNestedString(outputs, "deployment_history", "resource_group_deployment_name")
	if err != nil {
		return err
	}
	failedDeploymentName, err := outputNestedString(outputs, "deployment_history", "failed_deployment_name")
	if err != nil {
		return err
	}
	subscriptionTemplateURI, err := outputNestedString(outputs, "deployment_history", "subscription_template_uri")
	if err != nil {
		return err
	}
	resourceGroupParametersURI, err := outputNestedString(outputs, "deployment_history", "resource_group_parameters_uri")
	if err != nil {
		return err
	}

	if _, err := runAzureCommand(
		azureBinary,
		infraDir,
		"deployment", "sub", "create",
		"--location", location,
		"--name", subscriptionDeploymentName,
		"--template-uri", subscriptionTemplateURI,
		"--only-show-errors",
		"--output", "json",
	); err != nil {
		return fmt.Errorf("create subscription deployment-history canary: %w", err)
	}

	kvTemplateBytes, err := os.ReadFile(filepath.Join(deploymentHistoryDir, "arm-templates", "kv-secrets.json"))
	if err != nil {
		return fmt.Errorf("read kv-secrets template: %w", err)
	}
	kvTemplate := map[string]any{}
	if err := json.Unmarshal(kvTemplateBytes, &kvTemplate); err != nil {
		return fmt.Errorf("parse kv-secrets template: %w", err)
	}

	resourceGroupURI := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Resources/deployments/%s",
		subscriptionID,
		resourceGroups["data"],
		resourceGroupDeploymentName,
	)
	if err := runAzureJSONCommand(
		azureBinary,
		infraDir,
		map[string]any{
			"properties": map[string]any{
				"mode":     "Incremental",
				"template": kvTemplate,
				"parametersLink": map[string]any{
					"uri":            resourceGroupParametersURI,
					"contentVersion": "1.0.0.0",
				},
			},
		},
		"rest",
		"--method", "put",
		"--uri", fmt.Sprintf("https://management.azure.com%s?api-version=2022-09-01", resourceGroupURI),
		"--only-show-errors",
		"--output", "json",
	); err != nil {
		return fmt.Errorf("create resource-group deployment-history canary: %w", err)
	}

	if _, err := waitForDeploymentState(azureBinary, infraDir, resourceGroupURI, []string{"Succeeded"}); err != nil {
		return err
	}

	failedTemplateBytes, err := os.ReadFile(filepath.Join(deploymentHistoryDir, "arm-templates", "app-failed.json"))
	if err != nil {
		return fmt.Errorf("read failed deployment template: %w", err)
	}
	failedTemplate := map[string]any{}
	if err := json.Unmarshal(failedTemplateBytes, &failedTemplate); err != nil {
		return fmt.Errorf("parse failed deployment template: %w", err)
	}

	failedURI := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Resources/deployments/%s",
		subscriptionID,
		resourceGroups["workload"],
		failedDeploymentName,
	)
	_, _ = runAzureCommand(
		azureBinary,
		infraDir,
		"rest",
		"--method", "put",
		"--uri", fmt.Sprintf("https://management.azure.com%s?api-version=2022-09-01", failedURI),
		"--body", string(mustJSON(map[string]any{
			"properties": map[string]any{
				"mode":     "Incremental",
				"template": failedTemplate,
			},
		})),
		"--only-show-errors",
		"--output", "json",
	)

	state, err := waitForDeploymentState(azureBinary, infraDir, failedURI, []string{"Failed", "Succeeded"})
	if err != nil {
		return err
	}
	if state != "Failed" {
		return fmt.Errorf("failed deployment canary did not persist in Failed state; saw %q", state)
	}

	fmt.Fprintln(progressWriter, "Deployment-history resource canaries created.")
	return nil
}

func mustJSON(payload any) []byte {
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func resolveSSHPublicKey(config AzureSetupConfig, progressWriter io.Writer) (string, error) {
	if strings.TrimSpace(config.SSHPublicKey) != "" {
		return strings.TrimSpace(config.SSHPublicKey), nil
	}
	if strings.TrimSpace(config.SSHPublicKeyFile) != "" {
		data, err := os.ReadFile(config.SSHPublicKeyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	privateKeyPath := filepath.Join(filepath.Dir(config.InfraDir), ".generated", "keys", "azure-lab-default")
	publicKeyPath := privateKeyPath + ".pub"
	if data, err := os.ReadFile(publicKeyPath); err == nil {
		fmt.Fprintf(progressWriter, "Using generated lab SSH key at %s\n", publicKeyPath)
		return strings.TrimSpace(string(data)), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	publicKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(publicKey), 0o644); err != nil {
		return "", err
	}
	fmt.Fprintf(progressWriter, "No SSH key was provided. Generated a lab RSA key at %s\n", publicKeyPath)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))), nil
}

package lab

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAzureSetupTFVarsUsesOneVariableModel(t *testing.T) {
	payload := BuildAzureSetupTFVars(AzureSetupConfig{
		Location:                      "centralus",
		NamePrefix:                    "hoazurelab",
		SSHPublicKey:                  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:                   "lower-cost",
		AKSVMSize:                     "Standard_D2s_v3",
		EnableRoleTrustsCanary:        true,
		EnableDeploymentHistoryCanary: true,
		EnableAzureML:                 false,
	})

	if payload["location"] != "centralus" {
		t.Fatalf("expected centralus location, got %#v", payload["location"])
	}
	if payload["compute_profile"] != "lower-cost" {
		t.Fatalf("expected lower-cost profile, got %#v", payload["compute_profile"])
	}
	if payload["aks_vm_size"] != "Standard_D2s_v3" {
		t.Fatalf("expected explicit AKS size, got %#v", payload["aks_vm_size"])
	}
	if payload["enable_role_trusts_canary"] != true {
		t.Fatalf("expected role-trust canary to default true, got %#v", payload["enable_role_trusts_canary"])
	}
	if payload["enable_deployment_history_canary"] != true {
		t.Fatalf("expected deployment-history canary to default true, got %#v", payload["enable_deployment_history_canary"])
	}
	if payload["enable_azure_ml"] != false {
		t.Fatalf("expected azure-ml lane to default false, got %#v", payload["enable_azure_ml"])
	}
}

func TestRunAzureSetupWritesTFVarsAndRunsTofuFlow(t *testing.T) {
	infraDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tofu.log")
	fakeTofuPath := filepath.Join(t.TempDir(), "fake-tofu")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeTofuPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tofu: %v", err)
	}

	var progress bytes.Buffer
	outputPath, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:       infraDir,
		Location:       "centralus",
		NamePrefix:     "hoazurelab",
		SSHPublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:    "lower-cost",
		AKSVMSize:      "Standard_D2s_v3",
		TofuBinary:     fakeTofuPath,
		ProgressWriter: &progress,
	})
	if err != nil {
		t.Fatalf("run azure setup: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful setup exit, got %d", exitCode)
	}

	tfvars := map[string]any{}
	if err := LoadJSON(outputPath, &tfvars); err != nil {
		t.Fatalf("load generated tfvars: %v", err)
	}
	if tfvars["location"] != "centralus" {
		t.Fatalf("expected centralus in generated tfvars, got %#v", tfvars["location"])
	}
	if tfvars["compute_profile"] != "lower-cost" {
		t.Fatalf("expected lower-cost profile in generated tfvars, got %#v", tfvars["compute_profile"])
	}
	if tfvars["enable_azure_ml"] != false {
		t.Fatalf("expected azure-ml lane to stay disabled by default, got %#v", tfvars["enable_azure_ml"])
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake tofu log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "init -input=false") {
		t.Fatalf("expected tofu init call, got %q", logText)
	}
	if !strings.Contains(logText, "apply -input=false -auto-approve -var-file "+outputPath) {
		t.Fatalf("expected tofu apply call, got %q", logText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "Wrote Azure setup inputs") {
		t.Fatalf("expected tfvars progress, got %q", progressText)
	}
	if !strings.Contains(progressText, "Azure environment setup completed.") {
		t.Fatalf("expected setup completion progress, got %q", progressText)
	}
}

func TestRunAzureSetupAddsAzureMLAsFollowUpInfrastructure(t *testing.T) {
	infraDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tofu.log")
	fakeTofuPath := filepath.Join(t.TempDir(), "fake-tofu")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeTofuPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tofu: %v", err)
	}

	var progress bytes.Buffer
	outputPath, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:       infraDir,
		Location:       "centralus",
		NamePrefix:     "hoazurelab",
		SSHPublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:    "default",
		AKSVMSize:      "Standard_D2s_v3",
		EnableAzureML:  true,
		TofuBinary:     fakeTofuPath,
		ProgressWriter: &progress,
	})
	if err != nil {
		t.Fatalf("run azure setup with azure-ml lane: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful setup exit, got %d", exitCode)
	}
	if outputPath == "" {
		t.Fatalf("expected output path")
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake tofu log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "-exclude=azurerm_machine_learning_workspace.main[0]") {
		t.Fatalf("expected core apply to exclude azure-ml workspace target, got %q", logText)
	}
	if !strings.Contains(logText, "-target=azurerm_machine_learning_workspace.main[0]") {
		t.Fatalf("expected follow-up apply to target azure-ml workspace, got %q", logText)
	}
	if !strings.Contains(progress.String(), "Running follow-up OpenTofu apply for Azure ML...") {
		t.Fatalf("expected azure-ml follow-up progress, got %q", progress.String())
	}
}

func TestRunAzureSetupGeneratesLabKeyWhenNoKeyIsProvided(t *testing.T) {
	infraDir := t.TempDir()
	var progress bytes.Buffer

	outputPath, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:       infraDir,
		Location:       "centralus",
		NamePrefix:     "hoazurelab",
		CostProfile:    "default",
		AKSVMSize:      "Standard_D2s_v3",
		WriteOnly:      true,
		ProgressWriter: &progress,
	})
	if err != nil {
		t.Fatalf("run azure setup with generated key: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful write-only setup exit, got %d", exitCode)
	}

	tfvars := map[string]any{}
	if err := LoadJSON(outputPath, &tfvars); err != nil {
		t.Fatalf("load generated tfvars: %v", err)
	}
	publicKeyValue, ok := tfvars["ssh_public_key"].(string)
	if !ok || !strings.HasPrefix(publicKeyValue, "ssh-rsa ") {
		t.Fatalf("expected generated RSA public key, got %#v", tfvars["ssh_public_key"])
	}
	if tfvars["enable_azure_ml"] != false {
		t.Fatalf("expected generated tfvars to keep azure-ml lane disabled by default, got %#v", tfvars["enable_azure_ml"])
	}

	privateKeyPath := filepath.Join(filepath.Dir(infraDir), ".generated", "keys", "azure-lab-default")
	if _, err := os.Stat(privateKeyPath); err != nil {
		t.Fatalf("expected generated private key: %v", err)
	}
	if _, err := os.Stat(privateKeyPath + ".pub"); err != nil {
		t.Fatalf("expected generated public key: %v", err)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "Generated a lab RSA key") {
		t.Fatalf("expected generated-key progress, got %q", progressText)
	}
}

func TestRunDeploymentHistoryCanariesUsesCrossPlatformGoFlow(t *testing.T) {
	infraDir := t.TempDir()
	deploymentHistoryDir := filepath.Join(infraDir, "canaries", "deployment-history")
	templateDir := filepath.Join(deploymentHistoryDir, "arm-templates")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("mkdir canary templates: %v", err)
	}
	for name, content := range map[string]string{
		"kv-secrets.json": `{"$schema":"x","contentVersion":"1.0.0.0","parameters":{},"resources":[],"outputs":{}}`,
		"app-failed.json": `{"$schema":"x","contentVersion":"1.0.0.0","resources":[],"outputs":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(templateDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write template %s: %v", name, err)
		}
	}

	tofuLogPath := filepath.Join(t.TempDir(), "tofu-output.log")
	fakeTofuPath := filepath.Join(t.TempDir(), "fake-tofu")
	fakeTofuScript := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(tofuLogPath)),
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}},"deployment_history":{"value":{"subscription_deployment_name":"sub-foundation","resource_group_deployment_name":"kv-secrets","failed_deployment_name":"app-failed","subscription_template_uri":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json","resource_group_parameters_uri":"https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json"}}}`,
		"EOF",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeTofuPath, []byte(fakeTofuScript), 0o755); err != nil {
		t.Fatalf("write fake tofu: %v", err)
	}

	azLogPath := filepath.Join(t.TempDir(), "az.log")
	fakeAzPath := filepath.Join(t.TempDir(), "fake-az")
	fakeAzScript := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(azLogPath)),
		"if [ \"$1\" = \"deployment\" ] && [ \"$2\" = \"sub\" ] && [ \"$3\" = \"create\" ]; then",
		"  echo '{}'",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"rest\" ] && [ \"$2\" = \"--method\" ] && [ \"$3\" = \"put\" ]; then",
		"  echo '{}'",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"rest\" ] && [ \"$2\" = \"--method\" ] && [ \"$3\" = \"get\" ]; then",
		"  case \"$@\" in",
		"    *app-failed*) printf 'Failed\\n' ;;",
		"    *) printf 'Succeeded\\n' ;;",
		"  esac",
		"  exit 0",
		"fi",
		"echo 'unexpected az invocation' >&2",
		"exit 1",
	}, "\n")
	if err := os.WriteFile(fakeAzPath, []byte(fakeAzScript), 0o755); err != nil {
		t.Fatalf("write fake az: %v", err)
	}

	var progress bytes.Buffer
	if err := runDeploymentHistoryCanaries(&progress, infraDir, deploymentHistoryDir, fakeTofuPath, fakeAzPath, "centralus"); err != nil {
		t.Fatalf("run deployment-history canaries: %v", err)
	}

	azLogData, err := os.ReadFile(azLogPath)
	if err != nil {
		t.Fatalf("read fake az log: %v", err)
	}
	azLogText := string(azLogData)
	if !strings.Contains(azLogText, "deployment sub create --location centralus --name sub-foundation") {
		t.Fatalf("expected subscription deployment create, got %q", azLogText)
	}
	if !strings.Contains(azLogText, "providers/Microsoft.Resources/deployments/kv-secrets") {
		t.Fatalf("expected resource-group deployment put, got %q", azLogText)
	}
	if !strings.Contains(azLogText, "providers/Microsoft.Resources/deployments/app-failed") {
		t.Fatalf("expected failed deployment record, got %q", azLogText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "Deployment-history resource canaries created.") {
		t.Fatalf("expected deployment-history progress, got %q", progressText)
	}
}

func TestRunAzureSetupRunsDeploymentHistoryCanariesOnlyWhenEnabled(t *testing.T) {
	infraDir := t.TempDir()
	deploymentHistoryDir := filepath.Join(infraDir, "canaries", "deployment-history", "arm-templates")
	if err := os.MkdirAll(deploymentHistoryDir, 0o755); err != nil {
		t.Fatalf("mkdir canary dir: %v", err)
	}
	for name, content := range map[string]string{
		"sub-foundation.json":        `{"outputs":{}}`,
		"kv-secrets.parameters.json": `{"parameters":{}}`,
		"kv-secrets.json":            `{"resources":[]}`,
		"app-failed.json":            `{"resources":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(deploymentHistoryDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write canary file %s: %v", name, err)
		}
	}

	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ] || [ \"$1\" = \"apply\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}},"deployment_history":{"value":{"subscription_deployment_name":"sub-foundation","resource_group_deployment_name":"kv-secrets","failed_deployment_name":"app-failed","subscription_template_uri":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json","resource_group_parameters_uri":"https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"deployment\" ] || [ \"$1\" = \"rest\" ]; then",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:       infraDir,
		Location:       "centralus",
		NamePrefix:     "hoazurelab",
		SSHPublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:    "default",
		AKSVMSize:      "Standard_D2s_v3",
		TofuBinary:     fakeToolPath,
		AzureCLIBinary: fakeToolPath,
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("expected successful setup without canaries, got exit=%d err=%v", exitCode, err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read tool log: %v", err)
	}
	if strings.Contains(string(logData), "deployment sub create") {
		t.Fatalf("expected deployment-history canaries to stay disabled by default, got %q", string(logData))
	}
}

func TestRunAzureSetupContinuesPostApplyStepsWhenCoreOutputsExist(t *testing.T) {
	infraDir := t.TempDir()
	deploymentHistoryDir := filepath.Join(infraDir, "canaries", "deployment-history", "arm-templates")
	if err := os.MkdirAll(deploymentHistoryDir, 0o755); err != nil {
		t.Fatalf("mkdir canary dir: %v", err)
	}
	for name, content := range map[string]string{
		"sub-foundation.json":        `{"outputs":{}}`,
		"kv-secrets.parameters.json": `{"parameters":{}}`,
		"kv-secrets.json":            `{"resources":[]}`,
		"app-failed.json":            `{"resources":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(deploymentHistoryDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write canary file %s: %v", name, err)
		}
	}

	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"apply\" ]; then",
		"  echo 'apim create failed' >&2",
		"  exit 1",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}},"deployment_history":{"value":{"subscription_deployment_name":"sub-foundation","resource_group_deployment_name":"kv-secrets","failed_deployment_name":"app-failed","subscription_template_uri":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json","resource_group_parameters_uri":"https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"deployment\" ] && [ \"$2\" = \"sub\" ] && [ \"$3\" = \"create\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"rest\" ] && [ \"$2\" = \"--method\" ] && [ \"$3\" = \"put\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"rest\" ] && [ \"$2\" = \"--method\" ] && [ \"$3\" = \"get\" ]; then",
		"  case \"$@\" in",
		"    *app-failed*) printf 'Failed\\n' ;;",
		"    *) printf 'Succeeded\\n' ;;",
		"  esac",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	var progress bytes.Buffer
	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:                      infraDir,
		Location:                      "centralus",
		NamePrefix:                    "hoazurelab",
		SSHPublicKey:                  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:                   "default",
		AKSVMSize:                     "Standard_D2s_v3",
		TofuBinary:                    fakeToolPath,
		AzureCLIBinary:                fakeToolPath,
		EnableDeploymentHistoryCanary: true,
		ProgressWriter:                &progress,
	})
	if err != nil {
		t.Fatalf("expected partial-apply continuation without hard error, got %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected warning exit code for partial apply, got %d", exitCode)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read tool log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "apply -input=false -auto-approve") {
		t.Fatalf("expected apply attempt, got %q", logText)
	}
	if !strings.Contains(logText, "deployment sub create --location centralus --name sub-foundation") {
		t.Fatalf("expected deployment-history step after partial apply, got %q", logText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "WARNING: OpenTofu apply did not complete cleanly, but core lab outputs are available.") {
		t.Fatalf("expected partial-apply warning, got %q", progressText)
	}
	if !strings.Contains(progressText, "Azure environment setup finished with warnings.") {
		t.Fatalf("expected warning completion message, got %q", progressText)
	}
}

func TestRunAzureSetupTreatsDeploymentHistoryFailureAsWarning(t *testing.T) {
	infraDir := t.TempDir()
	deploymentHistoryDir := filepath.Join(infraDir, "canaries", "deployment-history", "arm-templates")
	if err := os.MkdirAll(deploymentHistoryDir, 0o755); err != nil {
		t.Fatalf("mkdir canary dir: %v", err)
	}
	for name, content := range map[string]string{
		"sub-foundation.json":        `{"outputs":{}}`,
		"kv-secrets.parameters.json": `{"parameters":{}}`,
		"kv-secrets.json":            `{"resources":[]}`,
		"app-failed.json":            `{"resources":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(deploymentHistoryDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write canary file %s: %v", name, err)
		}
	}

	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ] || [ \"$1\" = \"apply\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}},"deployment_history":{"value":{"subscription_deployment_name":"sub-foundation","resource_group_deployment_name":"kv-secrets","failed_deployment_name":"app-failed","subscription_template_uri":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json","resource_group_parameters_uri":"https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"deployment\" ] && [ \"$2\" = \"sub\" ] && [ \"$3\" = \"create\" ]; then",
		"  echo 'blocked by policy' >&2",
		"  exit 1",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	var progress bytes.Buffer
	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:                      infraDir,
		Location:                      "centralus",
		NamePrefix:                    "hoazurelab",
		SSHPublicKey:                  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:                   "default",
		AKSVMSize:                     "Standard_D2s_v3",
		TofuBinary:                    fakeToolPath,
		AzureCLIBinary:                fakeToolPath,
		EnableDeploymentHistoryCanary: true,
		ProgressWriter:                &progress,
	})
	if err != nil {
		t.Fatalf("expected canary warning without hard error, got %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful exit code with warning-only canary failure, got %d", exitCode)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "WARNING: deployment-history resource canaries were not created automatically:") {
		t.Fatalf("expected canary warning, got %q", progressText)
	}
	if !strings.Contains(progressText, "Azure environment setup completed with warnings.") {
		t.Fatalf("expected warning completion message, got %q", progressText)
	}
}

func TestRunAzureSetupSplitsCoreAndFollowUpInfrastructure(t *testing.T) {
	infraDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ] || [ \"$1\" = \"apply\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:     infraDir,
		Location:     "centralus",
		NamePrefix:   "hoazurelab",
		SSHPublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:  "default",
		AKSVMSize:    "Standard_D2s_v3",
		TofuBinary:   fakeToolPath,
	})
	if err != nil {
		t.Fatalf("expected successful setup, got %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful exit code, got %d", exitCode)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read tool log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "apply -input=false -auto-approve") {
		t.Fatalf("expected core apply, got %q", logText)
	}
	for _, target := range []string{
		"-exclude=azurerm_api_management.main",
		"-exclude=azurerm_kubernetes_cluster.main",
		"-exclude=azurerm_application_gateway.edge",
	} {
		if !strings.Contains(logText, target) {
			t.Fatalf("expected core apply to exclude follow-up target %q, got %q", target, logText)
		}
	}
	for _, target := range []string{
		"-target=azurerm_api_management.main",
		"-target=azurerm_api_management_named_value.backend_base",
		"-target=azurerm_kubernetes_cluster.main",
		"-target=azurerm_web_application_firewall_policy.application_gateway",
	} {
		if !strings.Contains(logText, target) {
			t.Fatalf("expected follow-up apply target %q, got %q", target, logText)
		}
	}
}

func TestRunAzureSetupTreatsFollowUpInfrastructureFailureAsWarning(t *testing.T) {
	infraDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"apply\" ]; then",
		"  case \"$@\" in",
		"    *-target=azurerm_kubernetes_cluster.main*)",
		"      echo 'aks capacity issue' >&2",
		"      exit 1",
		"      ;;",
		"    *)",
		"      exit 0",
		"      ;;",
		"  esac",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	var progress bytes.Buffer
	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:       infraDir,
		Location:       "centralus",
		NamePrefix:     "hoazurelab",
		SSHPublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:    "default",
		AKSVMSize:      "Standard_D2s_v3",
		TofuBinary:     fakeToolPath,
		ProgressWriter: &progress,
	})
	if err != nil {
		t.Fatalf("expected warning-only follow-up failure, got %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful exit code with warning-only follow-up failure, got %d", exitCode)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "WARNING: AKS follow-up infrastructure was not applied automatically:") {
		t.Fatalf("expected follow-up warning, got %q", progressText)
	}
	if !strings.Contains(progressText, "Azure environment setup completed with warnings.") {
		t.Fatalf("expected warning completion message, got %q", progressText)
	}
}

func TestRunAzureSetupCreatesHumanUserViewpointsWhenEnabled(t *testing.T) {
	infraDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tool.log")
	fakeToolPath := filepath.Join(t.TempDir(), "fake-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"init\" ] || [ \"$1\" = \"apply\" ]; then",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"output\" ]; then",
		"cat <<'EOF'",
		`{"subscription_id":{"value":"sub-123"},"resource_group_names":{"value":{"data":"rg-data","workload":"rg-workload"}}}`,
		"EOF",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"rest\" ]; then",
		"cat <<'EOF'",
		`{"value":[{"verifiedDomains":[{"name":"example.onmicrosoft.com","isDefault":true,"isInitial":true}]}]}`,
		"EOF",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"ad\" ] && [ \"$2\" = \"user\" ] && [ \"$3\" = \"create\" ]; then",
		"  case \"$@\" in",
		"    *hodev*) printf '{\"id\":\"user-dev-object-id\"}\\n' ;;",
		"    *) printf '{\"id\":\"user-business-object-id\"}\\n' ;;",
		"  esac",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"role\" ] && [ \"$2\" = \"assignment\" ] && [ \"$3\" = \"create\" ]; then",
		"  printf '{}'\\n",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	humanUserOutputPath := filepath.Join(t.TempDir(), "human-viewpoints.json")
	var progress bytes.Buffer
	_, exitCode, err := RunAzureSetup(AzureSetupConfig{
		InfraDir:                  infraDir,
		Location:                  "centralus",
		NamePrefix:                "hoazurelab",
		SSHPublicKey:              "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest",
		CostProfile:               "default",
		AKSVMSize:                 "Standard_D2s_v3",
		TofuBinary:                fakeToolPath,
		AzureCLIBinary:            fakeToolPath,
		EnableHumanUserViewpoints: true,
		HumanUserOutputPath:       humanUserOutputPath,
		ProgressWriter:            &progress,
	})
	if err != nil {
		t.Fatalf("expected human-user setup to succeed, got %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful exit code, got %d", exitCode)
	}

	var payload humanUserViewpointOutput
	if err := LoadJSON(humanUserOutputPath, &payload); err != nil {
		t.Fatalf("load generated human-user payload: %v", err)
	}
	if payload.Domain != "example.onmicrosoft.com" {
		t.Fatalf("expected tenant domain in generated payload, got %#v", payload.Domain)
	}
	devUser, ok := payload.Users["dev_user"]
	if !ok {
		t.Fatalf("expected dev_user entry, got %#v", payload.Users)
	}
	if !strings.HasPrefix(devUser.DisplayName, "HOdev") {
		t.Fatalf("expected lab-style dev display name, got %#v", devUser.DisplayName)
	}
	if !strings.HasPrefix(devUser.MailNickname, "hodev") {
		t.Fatalf("expected lab-style dev nickname, got %#v", devUser.MailNickname)
	}
	if !strings.HasSuffix(devUser.UserPrincipalName, "@example.onmicrosoft.com") {
		t.Fatalf("expected tenant-domain UPN, got %#v", devUser.UserPrincipalName)
	}
	if len(devUser.Password) != 30 {
		t.Fatalf("expected generated 30-character password, got length %d", len(devUser.Password))
	}
	businessUser, ok := payload.Users["business_user"]
	if !ok {
		t.Fatalf("expected business_user entry, got %#v", payload.Users)
	}
	if businessUser.RoleName != "Reader" {
		t.Fatalf("expected lower-visibility Reader role, got %#v", businessUser.RoleName)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read tool log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "ad user create --display-name") {
		t.Fatalf("expected user creation calls, got %q", logText)
	}
	if !strings.Contains(logText, "role assignment create --assignee-object-id user-dev-object-id --assignee-principal-type User --role Contributor --scope /subscriptions/sub-123/resourceGroups/rg-workload") {
		t.Fatalf("expected dev user role assignment, got %q", logText)
	}
	if !strings.Contains(logText, "role assignment create --assignee-object-id user-business-object-id --assignee-principal-type User --role Reader --scope /subscriptions/sub-123/resourceGroups/rg-workload") {
		t.Fatalf("expected business user role assignment, got %q", logText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "Human-user viewpoints created and recorded at") {
		t.Fatalf("expected human-user progress, got %q", progressText)
	}
}

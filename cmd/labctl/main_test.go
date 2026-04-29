package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ho-azure-lab/internal/lab"
)

func TestSetupAzureEnvironmentDefaultsWriteExpectedTFVars(t *testing.T) {
	infraDir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "azure.auto.tfvars.json")

	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()

	os.Args = []string{
		"labctl",
		"setup-azure-environment",
		"--infra-dir", infraDir,
		"--output", outputPath,
		"--write-only",
	}

	if exitCode := run(); exitCode != 0 {
		t.Fatalf("expected successful setup-azure-environment run, got %d", exitCode)
	}

	tfvars := map[string]any{}
	if err := lab.LoadJSON(outputPath, &tfvars); err != nil {
		t.Fatalf("load generated tfvars: %v", err)
	}
	if tfvars["location"] != "centralus" {
		t.Fatalf("expected centralus default location, got %#v", tfvars["location"])
	}
	if tfvars["compute_profile"] != "default" {
		t.Fatalf("expected default cost profile, got %#v", tfvars["compute_profile"])
	}
	if tfvars["enable_role_trusts_canary"] != true {
		t.Fatalf("expected role-trust canary default true, got %#v", tfvars["enable_role_trusts_canary"])
	}
	if tfvars["enable_deployment_history_canary"] != true {
		t.Fatalf("expected deployment-history canary default true, got %#v", tfvars["enable_deployment_history_canary"])
	}
	if tfvars["enable_azure_ml"] != false {
		t.Fatalf("expected azure-ml lane default false, got %#v", tfvars["enable_azure_ml"])
	}
	if tfvars["enable_deployment_path_addin"] != false {
		t.Fatalf("expected deployment-path add-in default false, got %#v", tfvars["enable_deployment_path_addin"])
	}
	if tfvars["enable_resource_hijacking_addin"] != false {
		t.Fatalf("expected resource-hijacking add-in default false, got %#v", tfvars["enable_resource_hijacking_addin"])
	}
	if tfvars["enable_exfil_addin"] != false {
		t.Fatalf("expected exfil add-in default false, got %#v", tfvars["enable_exfil_addin"])
	}
	if tfvars["enable_compute_control_addin"] != false {
		t.Fatalf("expected compute-control add-in default false, got %#v", tfvars["enable_compute_control_addin"])
	}
	if tfvars["enable_persistence_addin"] != false {
		t.Fatalf("expected persistence add-in default false, got %#v", tfvars["enable_persistence_addin"])
	}
	if sshKey, ok := tfvars["ssh_public_key"].(string); !ok || !strings.HasPrefix(sshKey, "ssh-rsa ") {
		t.Fatalf("expected generated lab ssh key, got %#v", tfvars["ssh_public_key"])
	}
}

func TestSetupEnvironmentPassesFlagsThroughToAzureSetup(t *testing.T) {
	infraDir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "azure.auto.tfvars.json")

	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()

	os.Args = []string{
		"labctl",
		"setup-environment",
		"--provider", "azure",
		"--infra-dir", infraDir,
		"--output", outputPath,
		"--write-only",
		"--location", "eastus2",
		"--cost-profile", "lower-cost",
		"--enable-azure-ml",
		"--enable-deployment-path-addin",
		"--enable-resource-hijacking-addin",
		"--enable-exfil-addin",
		"--enable-compute-control-addin",
		"--enable-persistence-addin",
	}

	if exitCode := run(); exitCode != 0 {
		t.Fatalf("expected successful setup-environment run, got %d", exitCode)
	}

	tfvars := map[string]any{}
	if err := lab.LoadJSON(outputPath, &tfvars); err != nil {
		t.Fatalf("load generated tfvars: %v", err)
	}
	if tfvars["location"] != "eastus2" {
		t.Fatalf("expected forwarded location, got %#v", tfvars["location"])
	}
	if tfvars["compute_profile"] != "lower-cost" {
		t.Fatalf("expected forwarded cost profile, got %#v", tfvars["compute_profile"])
	}
	if tfvars["enable_role_trusts_canary"] != true {
		t.Fatalf("expected role-trust canary to stay enabled in thin setup flow, got %#v", tfvars["enable_role_trusts_canary"])
	}
	if tfvars["enable_deployment_history_canary"] != true {
		t.Fatalf("expected deployment-history canary to stay enabled in thin setup flow, got %#v", tfvars["enable_deployment_history_canary"])
	}
	if tfvars["enable_azure_ml"] != true {
		t.Fatalf("expected azure-ml lane to forward through the thin setup flow, got %#v", tfvars["enable_azure_ml"])
	}
	workspaceName, _ := tfvars["azure_ml_workspace_name"].(string)
	if !strings.HasPrefix(workspaceName, "aml2-ops-") {
		t.Fatalf("expected generated azure-ml workspace name, got %#v", tfvars["azure_ml_workspace_name"])
	}
	if tfvars["enable_deployment_path_addin"] != true {
		t.Fatalf("expected deployment-path add-in to forward through the thin setup flow, got %#v", tfvars["enable_deployment_path_addin"])
	}
	if tfvars["enable_resource_hijacking_addin"] != true {
		t.Fatalf("expected resource-hijacking add-in to forward through the thin setup flow, got %#v", tfvars["enable_resource_hijacking_addin"])
	}
	if tfvars["enable_exfil_addin"] != true {
		t.Fatalf("expected exfil add-in to forward through the thin setup flow, got %#v", tfvars["enable_exfil_addin"])
	}
	if tfvars["enable_compute_control_addin"] != true {
		t.Fatalf("expected compute-control add-in to forward through the thin setup flow, got %#v", tfvars["enable_compute_control_addin"])
	}
	if tfvars["enable_persistence_addin"] != true {
		t.Fatalf("expected persistence add-in to forward through the thin setup flow, got %#v", tfvars["enable_persistence_addin"])
	}
}

func TestApplyRunProfileFileMergesSelectors(t *testing.T) {
	profilePath := filepath.Join(t.TempDir(), "profile.json")
	if err := lab.WriteJSON(profilePath, lab.RunProfileDefinition{
		Profile:   "helper-before-family",
		Viewpoint: "admin",
		Commands:  []string{"webjobs", "container-apps-jobs"},
		Families:  []string{"persistence"},
	}); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	runProfile := ""
	commands := "vm-extensions"
	families := ""
	viewpoint := "all"
	if err := applyRunProfileFile(profilePath, &runProfile, &commands, &families, &viewpoint); err != nil {
		t.Fatalf("apply profile: %v", err)
	}
	if runProfile != "helper-before-family" {
		t.Fatalf("expected profile from file, got %q", runProfile)
	}
	if commands != "vm-extensions,webjobs,container-apps-jobs" {
		t.Fatalf("expected merged command selectors, got %q", commands)
	}
	if families != "persistence" {
		t.Fatalf("expected family selector from file, got %q", families)
	}
	if viewpoint != "admin" {
		t.Fatalf("expected viewpoint from file, got %q", viewpoint)
	}
}

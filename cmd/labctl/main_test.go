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
}

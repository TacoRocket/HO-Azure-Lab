package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunFlagsEnvVarsFindingDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-env-vars-finding-drift-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-env-vars-finding-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "env-vars",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/env-vars/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "env-vars", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"env_vars":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api","asset_kind":"AppService","asset_name":"app-public-api","key_vault_reference_identity":null,"location":"centralus","looks_sensitive":true,"reference_target":null,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"],"resource_group":"rg-apps","setting_name":"DB_PASSWORD","summary":"summary","value_type":"plain-text","workload_identity_ids":[],"workload_identity_type":"SystemAssigned","workload_principal_id":"principal-app-public"},{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders","asset_kind":"FunctionApp","asset_name":"func-orders","key_vault_reference_identity":"SystemAssigned","location":"centralus","looks_sensitive":true,"reference_target":"kv-open.vault.azure.net/secrets/payment-api-key","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"],"resource_group":"rg-apps","setting_name":"PAYMENT_API_KEY","summary":"summary","value_type":"keyvault-ref","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"SystemAssigned, UserAssigned","workload_principal_id":"principal-func-orders"}],"findings":[{"description":"AppService 'app-public-api' stores setting 'DB_PASSWORD' as plain-text management-plane config.","id":"env-var-plain-sensitive-/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api-DB_PASSWORD","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"],"severity":"medium","title":"Sensitive-looking app setting is stored in plain text"}],"issues":[],"metadata":{"command":"env-vars","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	keyVaultIdentity := "SystemAssigned"
	functionIdentityType := "SystemAssigned, UserAssigned"
	functionPrincipalID := "principal-func-orders"
	appIdentityType := "SystemAssigned"
	appPrincipalID := "principal-app-public"
	if err := WriteJSON(filepath.Join(payloadDir, "live-env-vars-context.json"), liveEnvVarsContextArtifact{
		Assets: []liveEnvVarAssetTruth{
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-empty-mi",
				AssetKind:            "AppService",
				AssetName:            "app-empty-mi",
				Location:             "centralus",
				ResourceGroup:        "rg-apps",
				SettingsReadable:     true,
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  stringPtr("principal-app-empty"),
			},
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
				AssetKind:            "AppService",
				AssetName:            "app-public-api",
				Location:             "centralus",
				ResourceGroup:        "rg-apps",
				SettingsReadable:     true,
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  &appPrincipalID,
			},
			{
				AssetID:                   "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
				AssetKind:                 "FunctionApp",
				AssetName:                 "func-orders",
				KeyVaultReferenceIdentity: &keyVaultIdentity,
				Location:                  "centralus",
				ResourceGroup:             "rg-apps",
				SettingsReadable:          true,
				WorkloadIdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				WorkloadIdentityType:      &functionIdentityType,
				WorkloadPrincipalID:       &functionPrincipalID,
			},
		},
		EnvVars: []liveEnvVarTruth{
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
				AssetKind:            "AppService",
				AssetName:            "app-public-api",
				Location:             "centralus",
				LooksSensitive:       true,
				ResourceGroup:        "rg-apps",
				SettingName:          "DB_PASSWORD",
				ValueType:            "plain-text",
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  &appPrincipalID,
			},
			{
				AssetID:                   "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
				AssetKind:                 "FunctionApp",
				AssetName:                 "func-orders",
				KeyVaultReferenceIdentity: &keyVaultIdentity,
				Location:                  "centralus",
				LooksSensitive:            true,
				ReferenceTarget:           stringPtr("kv-open.vault.azure.net/secrets/payment-api-key"),
				ResourceGroup:             "rg-apps",
				SettingName:               "PAYMENT_API_KEY",
				ValueType:                 "keyvault-ref",
				WorkloadIdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				WorkloadIdentityType:      &functionIdentityType,
				WorkloadPrincipalID:       &functionPrincipalID,
			},
		},
	}); err != nil {
		t.Fatalf("write env-vars context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected env-vars finding drift, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "expected env-vars finding") && strings.Contains(finding.Summary, "env-var-keyvault-ref-") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected env-vars keyvault finding drift, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsMatchingEnvVarsContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-env-vars-match-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-env-vars-match-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "env-vars",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/env-vars/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "env-vars", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"env_vars":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api","asset_kind":"AppService","asset_name":"app-public-api","key_vault_reference_identity":null,"location":"centralus","looks_sensitive":true,"reference_target":null,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"],"resource_group":"rg-apps","setting_name":"DB_PASSWORD","summary":"summary","value_type":"plain-text","workload_identity_ids":[],"workload_identity_type":"SystemAssigned","workload_principal_id":"principal-app-public"},{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders","asset_kind":"FunctionApp","asset_name":"func-orders","key_vault_reference_identity":"SystemAssigned","location":"centralus","looks_sensitive":true,"reference_target":"kv-open.vault.azure.net/secrets/payment-api-key","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"],"resource_group":"rg-apps","setting_name":"PAYMENT_API_KEY","summary":"summary","value_type":"keyvault-ref","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"SystemAssigned, UserAssigned","workload_principal_id":"principal-func-orders"},{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders","asset_kind":"FunctionApp","asset_name":"func-orders","key_vault_reference_identity":"SystemAssigned","location":"centralus","looks_sensitive":true,"reference_target":null,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"],"resource_group":"rg-apps","setting_name":"AzureWebJobsStorage","summary":"summary","value_type":"plain-text","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"SystemAssigned, UserAssigned","workload_principal_id":"principal-func-orders"}],"findings":[{"description":"AppService 'app-public-api' stores setting 'DB_PASSWORD' as plain-text management-plane config.","id":"env-var-plain-sensitive-/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api-DB_PASSWORD","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"],"severity":"medium","title":"Sensitive-looking app setting is stored in plain text"},{"description":"FunctionApp 'func-orders' maps setting 'PAYMENT_API_KEY' to Key Vault-backed configuration (kv-open.vault.azure.net/secrets/payment-api-key).","id":"env-var-keyvault-ref-/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders-PAYMENT_API_KEY","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"],"severity":"low","title":"App setting references Key Vault"},{"description":"FunctionApp 'func-orders' stores setting 'AzureWebJobsStorage' as plain-text management-plane config.","id":"env-var-plain-sensitive-/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders-AzureWebJobsStorage","related_ids":["/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"],"severity":"medium","title":"Sensitive-looking app setting is stored in plain text"}],"issues":[],"metadata":{"command":"env-vars","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	keyVaultIdentity := "SystemAssigned"
	appIdentityType := "SystemAssigned"
	appPrincipalID := "principal-app-public"
	functionIdentityType := "SystemAssigned, UserAssigned"
	functionPrincipalID := "principal-func-orders"
	if err := WriteJSON(filepath.Join(payloadDir, "live-env-vars-context.json"), liveEnvVarsContextArtifact{
		Assets: []liveEnvVarAssetTruth{
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-empty-mi",
				AssetKind:            "AppService",
				AssetName:            "app-empty-mi",
				Location:             "centralus",
				ResourceGroup:        "rg-apps",
				SettingsReadable:     true,
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  stringPtr("principal-app-empty"),
			},
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
				AssetKind:            "AppService",
				AssetName:            "app-public-api",
				Location:             "centralus",
				ResourceGroup:        "rg-apps",
				SettingsReadable:     true,
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  &appPrincipalID,
			},
			{
				AssetID:                   "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
				AssetKind:                 "FunctionApp",
				AssetName:                 "func-orders",
				KeyVaultReferenceIdentity: &keyVaultIdentity,
				Location:                  "centralus",
				ResourceGroup:             "rg-apps",
				SettingsReadable:          true,
				WorkloadIdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				WorkloadIdentityType:      &functionIdentityType,
				WorkloadPrincipalID:       &functionPrincipalID,
			},
		},
		EnvVars: []liveEnvVarTruth{
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
				AssetKind:            "AppService",
				AssetName:            "app-public-api",
				Location:             "centralus",
				LooksSensitive:       true,
				ResourceGroup:        "rg-apps",
				SettingName:          "DB_PASSWORD",
				ValueType:            "plain-text",
				WorkloadIdentityType: &appIdentityType,
				WorkloadPrincipalID:  &appPrincipalID,
			},
			{
				AssetID:                   "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
				AssetKind:                 "FunctionApp",
				AssetName:                 "func-orders",
				KeyVaultReferenceIdentity: &keyVaultIdentity,
				Location:                  "centralus",
				LooksSensitive:            true,
				ReferenceTarget:           stringPtr("kv-open.vault.azure.net/secrets/payment-api-key"),
				ResourceGroup:             "rg-apps",
				SettingName:               "PAYMENT_API_KEY",
				ValueType:                 "keyvault-ref",
				WorkloadIdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				WorkloadIdentityType:      &functionIdentityType,
				WorkloadPrincipalID:       &functionPrincipalID,
			},
			{
				AssetID:                   "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
				AssetKind:                 "FunctionApp",
				AssetName:                 "func-orders",
				KeyVaultReferenceIdentity: &keyVaultIdentity,
				Location:                  "centralus",
				LooksSensitive:            true,
				ResourceGroup:             "rg-apps",
				SettingName:               "AzureWebJobsStorage",
				ValueType:                 "plain-text",
				WorkloadIdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				WorkloadIdentityType:      &functionIdentityType,
				WorkloadPrincipalID:       &functionPrincipalID,
			},
		},
	}); err != nil {
		t.Fatalf("write env-vars context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected matching env-vars context to pass cleanly, got %#v", summary.Findings)
	}
}

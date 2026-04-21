package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateLiveRunAcceptsResourceTrustRows(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-resource-trusts-pass-test",
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
		RunID:      "live-resource-trusts-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "resource-trusts",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/resource-trusts/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "resource-trusts", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"resource_trusts":[{"confidence":"confirmed","exposure":"high","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic"],"resource_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","resource_name":"stpublic","resource_type":"StorageAccount","summary":"Storage account 'stpublic' permits public blob access from the public network.","target":"public-network","trust_type":"anonymous-blob-access"},{"confidence":"confirmed","exposure":"medium","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic"],"resource_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","resource_name":"stpublic","resource_type":"StorageAccount","summary":"Storage account 'stpublic' accepts public network traffic by default.","target":"public-network","trust_type":"public-network-default"},{"confidence":"confirmed","exposure":"restricted","related_ids":["/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-private"],"resource_id":"/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-private","resource_name":"kv-private","resource_type":"KeyVault","summary":"Key Vault 'kv-private' exposes a private endpoint path through Azure Private Link.","target":"private-link","trust_type":"private-endpoint"}],"findings":[{"id":"storage-public-/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","title":"Storage account allows public blob access","severity":"high","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic"]},{"id":"storage-firewall-open-/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","title":"Storage account network default action is Allow","severity":"medium","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic"]}],"issues":[],"metadata":{"command":"resource-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-storage-context.json"), liveStorageContextArtifact{
		StorageAssets: []liveStorageTruth{{
			ID:                   "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
			Name:                 "stpublic",
			ResourceGroup:        "rg-data",
			Location:             "centralus",
			PublicAccess:         true,
			PublicNetworkAccess:  "Enabled",
			NetworkDefaultAction: "Allow",
		}},
	}); err != nil {
		t.Fatalf("write storage context: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-keyvault-context.json"), liveKeyVaultContextArtifact{
		KeyVaults: []liveKeyVaultTruth{{
			ID:                     "/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-private",
			Name:                   "kv-private",
			ResourceGroup:          "rg-secrets",
			Location:               "centralus",
			PublicNetworkAccess:    "Disabled",
			NetworkDefaultAction:   "Deny",
			PrivateEndpointEnabled: true,
		}},
	}); err != nil {
		t.Fatalf("write keyvault context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected resource-trusts seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsPurgeBleedInResourceTrusts(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-resource-trusts-purge-bleed-test",
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
		RunID:      "live-resource-trusts-purge-bleed-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "resource-trusts",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/resource-trusts/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "resource-trusts", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"resource_trusts":[],"findings":[{"id":"keyvault-purge-protection-disabled-/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","title":"Key Vault purge protection is disabled","severity":"medium","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open"]}],"issues":[],"metadata":{"command":"resource-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-storage-context.json"), liveStorageContextArtifact{}); err != nil {
		t.Fatalf("write storage context: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-keyvault-context.json"), liveKeyVaultContextArtifact{}); err != nil {
		t.Fatalf("write keyvault context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected purge bleed finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingResourceTrustRow(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-resource-trusts-drift-test",
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
		RunID:      "live-resource-trusts-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "resource-trusts",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/resource-trusts/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "resource-trusts", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"resource_trusts":[],"findings":[],"issues":[],"metadata":{"command":"resource-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-storage-context.json"), liveStorageContextArtifact{
		StorageAssets: []liveStorageTruth{{
			ID:                   "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
			Name:                 "stpublic",
			ResourceGroup:        "rg-data",
			PublicAccess:         true,
			PublicNetworkAccess:  "Enabled",
			NetworkDefaultAction: "Allow",
		}},
	}); err != nil {
		t.Fatalf("write storage context: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-keyvault-context.json"), liveKeyVaultContextArtifact{}); err != nil {
		t.Fatalf("write keyvault context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected resource-trusts drift finding, got %#v", summary.Findings)
	}
}

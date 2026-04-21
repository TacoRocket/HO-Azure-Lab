package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateLiveRunAcceptsTokensCredentialsCanaryRows(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-tokens-credentials-pass-test",
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
		RunID:      "live-tokens-credentials-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "tokens-credentials",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/tokens-credentials/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "tokens-credentials", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"surfaces":[{"access_path":"app-setting","asset_id":"/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-public-api","kind":"AppService","asset":"app-public-api","operator_signal":"setting=DB_PASSWORD","priority":"high","surface":"plain-text-secret"},{"access_path":"app-setting","asset_id":"/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/func-orders","kind":"FunctionApp","asset":"func-orders","operator_signal":"setting=AzureWebJobsStorage","priority":"high","surface":"plain-text-secret"},{"access_path":"app-setting","asset_id":"/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/func-orders","kind":"FunctionApp","asset":"func-orders","operator_signal":"target=kvlabopen.vault.azure.net/secrets/payment-api-key; identity=ua-orders","priority":"medium","surface":"keyvault-reference"},{"access_path":"deployment-history","asset_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets","kind":"ArmDeployment","asset":"kv-secrets","operator_signal":"outputs=1; providers=0","priority":"medium","surface":"deployment-output"},{"access_path":"deployment-history","asset_id":"/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","kind":"ArmDeployment","asset":"sub-foundation","operator_signal":"template=example.blob.core.windows.net/templates/sub-foundation.json","priority":"low","surface":"linked-deployment-content"},{"access_path":"workload-identity","asset_id":"/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-empty-mi","kind":"AppService","asset":"app-empty-mi","operator_signal":"SystemAssigned","priority":"medium","surface":"managed-identity-token"},{"access_path":"imds","asset_id":"/subscriptions/sub-123/resourceGroups/RG-APP/providers/Microsoft.Compute/virtualMachines/vm-web-01","kind":"VM","asset":"vm-web-01","operator_signal":"public-ip=20.20.20.20; identities=1","priority":"high","surface":"managed-identity-token"}],"findings":[],"issues":[],"metadata":{"command":"tokens-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-tokens-credentials-context.json"), liveTokensCredentialsContextArtifact{
		ExpectedSurfaces: []liveTokensCredentialSurfaceTruth{
			{AccessPath: "app-setting", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-public-api", AssetKind: "AppService", AssetName: "app-public-api", OperatorSignal: "setting=DB_PASSWORD", Priority: "high", SurfaceType: "plain-text-secret"},
			{AccessPath: "app-setting", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/func-orders", AssetKind: "FunctionApp", AssetName: "func-orders", OperatorSignal: "setting=AzureWebJobsStorage", Priority: "high", SurfaceType: "plain-text-secret"},
			{AccessPath: "app-setting", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/func-orders", AssetKind: "FunctionApp", AssetName: "func-orders", OperatorSignal: "target=kvlabopen.vault.azure.net/secrets/payment-api-key; identity=ua-orders", Priority: "medium", SurfaceType: "keyvault-reference"},
			{AccessPath: "deployment-history", AssetID: "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets", AssetKind: "ArmDeployment", AssetName: "kv-secrets", OperatorSignal: "outputs=1; providers=0", Priority: "medium", SurfaceType: "deployment-output"},
			{AccessPath: "deployment-history", AssetID: "/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation", AssetKind: "ArmDeployment", AssetName: "sub-foundation", OperatorSignal: "template=example.blob.core.windows.net/templates/sub-foundation.json", Priority: "low", SurfaceType: "linked-deployment-content"},
			{AccessPath: "workload-identity", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-empty-mi", AssetKind: "AppService", AssetName: "app-empty-mi", OperatorSignal: "SystemAssigned", Priority: "medium", SurfaceType: "managed-identity-token"},
			{AccessPath: "imds", AssetID: "/subscriptions/sub-123/resourceGroups/RG-APP/providers/Microsoft.Compute/virtualMachines/vm-web-01", AssetKind: "VM", AssetName: "vm-web-01", OperatorSignal: "public-ip=20.20.20.20; identities=1", Priority: "high", SurfaceType: "managed-identity-token"},
		},
	}); err != nil {
		t.Fatalf("write tokens-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected tokens-credentials seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsBlockedReducedTokensCredentials(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-tokens-credentials-reduced-test",
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
		RunID:      "live-tokens-credentials-reduced-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "tokens-credentials",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/tokens-credentials/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "tokens-credentials", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"surfaces":[{"access_path":"workload-identity","asset_id":"/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-empty-mi","kind":"AppService","asset":"app-empty-mi","operator_signal":"SystemAssigned","priority":"medium","surface":"managed-identity-token"}],"findings":[],"issues":[{"kind":"collection_error","scope":"env_vars[rg-app/app-public-api]","message":"blocked","context":{"collector":"env_vars[rg-app/app-public-api]"}}],"metadata":{"command":"tokens-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-tokens-credentials-context.json"), liveTokensCredentialsContextArtifact{
		ExpectedSurfaces: []liveTokensCredentialSurfaceTruth{
			{AccessPath: "workload-identity", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-empty-mi", AssetKind: "AppService", AssetName: "app-empty-mi", OperatorSignal: "SystemAssigned", Priority: "medium", SurfaceType: "managed-identity-token"},
		},
		BlockedAppSettingRead: []liveTokensCredentialBlockedAssetTruth{
			{AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-public-api", AssetName: "app-public-api", Scope: "env_vars[rg-app/app-public-api]"},
		},
	}); err != nil {
		t.Fatalf("write tokens-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected blocked reduced tokens-credentials seam to pass, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingTokensCredentialSurface(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-tokens-credentials-drift-test",
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
		RunID:      "live-tokens-credentials-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "tokens-credentials",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/tokens-credentials/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "tokens-credentials", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"surfaces":[],"findings":[],"issues":[],"metadata":{"command":"tokens-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-tokens-credentials-context.json"), liveTokensCredentialsContextArtifact{
		ExpectedSurfaces: []liveTokensCredentialSurfaceTruth{
			{AccessPath: "app-setting", AssetID: "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/app-public-api", AssetKind: "AppService", AssetName: "app-public-api", OperatorSignal: "setting=DB_PASSWORD", Priority: "high", SurfaceType: "plain-text-secret"},
		},
	}); err != nil {
		t.Fatalf("write tokens-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected tokens-credentials drift finding, got %#v", summary.Findings)
	}
}

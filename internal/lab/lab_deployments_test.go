package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunAcceptsArmDeploymentsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-arm-deployments-pass-test",
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
		RunID:      "live-arm-deployments-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "arm-deployments",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/arm-deployments/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "arm-deployments", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"deployments":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed","mode":"Incremental","name":"app-failed","output_resource_count":0,"outputs_count":0,"parameters_link":null,"providers":["Microsoft.Web"],"provisioning_state":"Failed","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed"],"resource_group":"rg-workload","scope":"/subscriptions/sub-123/resourceGroups/rg-workload","scope_type":"resource_group","template_link":null},{"id":"/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","mode":"Incremental","name":"sub-foundation","output_resource_count":3,"outputs_count":2,"parameters_link":null,"providers":["Microsoft.Network","Microsoft.Storage"],"provisioning_state":"Succeeded","related_ids":["/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"],"resource_group":null,"scope":"/subscriptions/sub-123","scope_type":"subscription","template_link":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json"},{"id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets","mode":"Incremental","name":"kv-secrets","output_resource_count":1,"outputs_count":1,"parameters_link":"https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json","providers":["Microsoft.KeyVault"],"provisioning_state":"Succeeded","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets"],"resource_group":"rg-data","scope":"/subscriptions/sub-123/resourceGroups/rg-data","scope_type":"resource_group","template_link":null}],"findings":[{"id":"arm-deployment-failed-/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed","severity":"medium","title":"Deployment did not complete successfully","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed"]},{"id":"arm-deployment-outputs-/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","severity":"medium","title":"Deployment exposes output values","description":"desc","related_ids":["/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"]},{"id":"arm-deployment-remote-link-/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","severity":"low","title":"Deployment references linked template content","description":"desc","related_ids":["/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"]},{"id":"arm-deployment-outputs-/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets","severity":"medium","title":"Deployment exposes output values","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets"]},{"id":"arm-deployment-remote-link-/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets","severity":"low","title":"Deployment references linked template content","description":"desc","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets"]}],"issues":[],"metadata":{"command":"arm-deployments","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-arm-deployments-context.json"), liveArmDeploymentsContextArtifact{
		Deployments: []liveArmDeploymentTruth{
			{
				ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed",
				Mode:                "Incremental",
				Name:                "app-failed",
				OutputResourceCount: 0,
				OutputsCount:        0,
				Providers:           []string{"Microsoft.Web"},
				ProvisioningState:   "Failed",
				RelatedIDs:          []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Resources/deployments/app-failed"},
				ResourceGroup:       stringPtr("rg-workload"),
				Scope:               "/subscriptions/sub-123/resourceGroups/rg-workload",
				ScopeType:           "resource_group",
			},
			{
				ID:                  "/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation",
				Mode:                "Incremental",
				Name:                "sub-foundation",
				OutputResourceCount: 3,
				OutputsCount:        2,
				Providers:           []string{"Microsoft.Network", "Microsoft.Storage"},
				ProvisioningState:   "Succeeded",
				RelatedIDs:          []string{"/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"},
				Scope:               "/subscriptions/sub-123",
				ScopeType:           "subscription",
				TemplateLink:        stringPtr("https://example.blob.core.windows.net/labproof/templates/sub-foundation.json"),
			},
			{
				ID:                  "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets",
				Mode:                "Incremental",
				Name:                "kv-secrets",
				OutputResourceCount: 1,
				OutputsCount:        1,
				ParametersLink:      stringPtr("https://example.blob.core.windows.net/labproof/parameters/kv-secrets.parameters.json"),
				Providers:           []string{"Microsoft.KeyVault"},
				ProvisioningState:   "Succeeded",
				RelatedIDs:          []string{"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Resources/deployments/kv-secrets"},
				ResourceGroup:       stringPtr("rg-data"),
				Scope:               "/subscriptions/sub-123/resourceGroups/rg-data",
				ScopeType:           "resource_group",
			},
		},
	}); err != nil {
		t.Fatalf("write arm-deployments context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected arm-deployments seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsArmDeploymentsFindingDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-arm-deployments-finding-drift-test",
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
		RunID:      "live-arm-deployments-finding-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "arm-deployments",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/arm-deployments/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "arm-deployments", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"deployments":[{"id":"/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","mode":"Incremental","name":"sub-foundation","output_resource_count":3,"outputs_count":2,"parameters_link":null,"providers":["Microsoft.Network","Microsoft.Storage"],"provisioning_state":"Succeeded","related_ids":["/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"],"resource_group":null,"scope":"/subscriptions/sub-123","scope_type":"subscription","template_link":"https://example.blob.core.windows.net/labproof/templates/sub-foundation.json"}],"findings":[{"id":"arm-deployment-outputs-/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation","severity":"medium","title":"Deployment exposes output values","description":"desc","related_ids":["/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"]}],"issues":[],"metadata":{"command":"arm-deployments","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-arm-deployments-context.json"), liveArmDeploymentsContextArtifact{
		Deployments: []liveArmDeploymentTruth{{
			ID:                  "/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation",
			Mode:                "Incremental",
			Name:                "sub-foundation",
			OutputResourceCount: 3,
			OutputsCount:        2,
			Providers:           []string{"Microsoft.Network", "Microsoft.Storage"},
			ProvisioningState:   "Succeeded",
			RelatedIDs:          []string{"/subscriptions/sub-123/providers/Microsoft.Resources/deployments/sub-foundation"},
			Scope:               "/subscriptions/sub-123",
			ScopeType:           "subscription",
			TemplateLink:        stringPtr("https://example.blob.core.windows.net/labproof/templates/sub-foundation.json"),
		}},
	}); err != nil {
		t.Fatalf("write arm-deployments context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected arm-deployments finding drift, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "remote-link finding") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected remote-link finding drift, got %#v", summary.Findings)
	}
}

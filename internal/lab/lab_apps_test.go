package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunAcceptsFunctionsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-functions-pass-test",
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
		RunID:      "live-functions-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "functions",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/functions/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "functions", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"function_apps":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","function_app":"func-orders","hostname":"func-orders.azurewebsites.net","public_network_access":"Enabled","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"SystemAssigned, UserAssigned","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"functions","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-functions-context.json"), liveFunctionsContextArtifact{
		FunctionApps: []liveFunctionTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
			Name:                "func-orders",
			Hostname:            "func-orders.azurewebsites.net",
			PublicNetworkAccess: "Enabled",
			IdentityType:        "SystemAssigned, UserAssigned",
			IdentityIDs:         []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
		}},
	}); err != nil {
		t.Fatalf("write functions context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected functions seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsFunctionsPublicNetworkDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-functions-public-network-drift-test",
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
		RunID:      "live-functions-public-network-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "functions",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/functions/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "functions", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"function_apps":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","function_app":"func-orders","hostname":"func-orders.azurewebsites.net","public_network_access":"Disabled","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"functions","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-functions-context.json"), liveFunctionsContextArtifact{
		FunctionApps: []liveFunctionTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
			Name:                "func-orders",
			Hostname:            "func-orders.azurewebsites.net",
			PublicNetworkAccess: "Enabled",
		}},
	}); err != nil {
		t.Fatalf("write functions context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected functions public network drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_network_access") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected functions public network drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsContainerAppsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-container-apps-pass-test",
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
		RunID:      "live-container-apps-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "container-apps",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/container-apps/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "container-apps", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"container_apps":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/containerapps/ca-public-api","name":"ca-public-api","default_hostname":"ca-public-api.region.azurecontainerapps.io","environment_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/managedEnvironments/cae-ops","external_ingress_enabled":true,"ingress_target_port":80,"ingress_transport":"Auto","latest_ready_revision_name":"ca-public-api--abc123","latest_revision_name":"ca-public-api--abc123","revision_mode":"Single","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"UserAssigned","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"container-apps","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	external := true
	targetPort := 80
	if err := WriteJSON(filepath.Join(payloadDir, "live-container-apps-context.json"), liveContainerAppsContextArtifact{
		ContainerApps: []liveContainerAppTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/containerapps/ca-public-api",
			Name:                "ca-public-api",
			DefaultHostname:     "ca-public-api.region.azurecontainerapps.io",
			EnvironmentID:       "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/managedEnvironments/cae-ops",
			ExternalIngress:     &external,
			IngressTargetPort:   &targetPort,
			IngressTransport:    "Auto",
			LatestReadyRevision: "ca-public-api--abc123",
			LatestRevision:      "ca-public-api--abc123",
			RevisionMode:        "Single",
			IdentityType:        "UserAssigned",
			IdentityIDs:         []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
		}},
	}); err != nil {
		t.Fatalf("write container apps context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected container-apps seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsContainerAppsExternalIngressDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-container-apps-external-ingress-drift-test",
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
		RunID:      "live-container-apps-external-ingress-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "container-apps",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/container-apps/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "container-apps", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"container_apps":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/containerapps/ca-public-api","name":"ca-public-api","default_hostname":"ca-public-api.region.azurecontainerapps.io","environment_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/managedEnvironments/cae-ops","external_ingress_enabled":false,"ingress_target_port":80,"ingress_transport":"Auto","latest_ready_revision_name":"ca-public-api--abc123","latest_revision_name":"ca-public-api--abc123","revision_mode":"Single","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"container-apps","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	external := true
	targetPort := 80
	if err := WriteJSON(filepath.Join(payloadDir, "live-container-apps-context.json"), liveContainerAppsContextArtifact{
		ContainerApps: []liveContainerAppTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/containerapps/ca-public-api",
			Name:                "ca-public-api",
			DefaultHostname:     "ca-public-api.region.azurecontainerapps.io",
			EnvironmentID:       "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.App/managedEnvironments/cae-ops",
			ExternalIngress:     &external,
			IngressTargetPort:   &targetPort,
			IngressTransport:    "Auto",
			LatestReadyRevision: "ca-public-api--abc123",
			LatestRevision:      "ca-public-api--abc123",
			RevisionMode:        "Single",
		}},
	}); err != nil {
		t.Fatalf("write container apps context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected container-apps external ingress drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "external_ingress_enabled") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected container-apps external ingress drift finding, got %#v", summary.Findings)
	}
}

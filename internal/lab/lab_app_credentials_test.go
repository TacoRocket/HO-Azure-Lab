package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateLiveRunAcceptsAppCredentialsCanaryRows(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-credentials-pass-test",
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
		RunID:      "live-app-credentials-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "app-credentials",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/app-credentials/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-credentials", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_credentials":[{"row_class":"directly_addable_federated_trust","target_object_type":"Application","target_object_id":"app-api-123","target_object_name":"ho-roletrust-api","backing_service_principal_id":"sp-api-123","backing_service_principal_name":"ho-roletrust-api","credential_type":"federated","control_path":"application-owner","role_context":"role context","tenant_context":"current-tenant","current_evidence":"evidence","missing_proof":"proof","operator_actionability":"action","recommended_fix_focus":"fix","summary":"summary","related_ids":["owner-1","app-api-123","sp-api-123"]},{"row_class":"directly_addable","target_object_type":"Application","target_object_id":"app-api-123","target_object_name":"ho-roletrust-api","backing_service_principal_id":"sp-api-123","backing_service_principal_name":"ho-roletrust-api","credential_type":"password-or-key","control_path":"application-owner","role_context":"role context","tenant_context":"current-tenant","current_evidence":"evidence","missing_proof":"","operator_actionability":"action","recommended_fix_focus":"fix","summary":"summary","related_ids":["owner-1","app-api-123","sp-api-123"]},{"row_class":"directly_addable","target_object_type":"ServicePrincipal","target_object_id":"sp-api-123","target_object_name":"ho-roletrust-api","backing_service_principal_id":"sp-api-123","backing_service_principal_name":"ho-roletrust-api","credential_type":"password-or-key","control_path":"service-principal-owner","role_context":"role context","tenant_context":"current-tenant","current_evidence":"evidence","missing_proof":"","operator_actionability":"action","recommended_fix_focus":"fix","summary":"summary","related_ids":["owner-1","sp-api-123"]},{"row_class":"federated_trust_present","target_object_type":"Application","target_object_id":"app-api-123","target_object_name":"ho-roletrust-api","backing_service_principal_id":"sp-api-123","backing_service_principal_name":"ho-roletrust-api","credential_type":"federated","control_path":"existing-federated-trust","role_context":"role context","tenant_context":"current-tenant","current_evidence":"evidence","missing_proof":"proof","operator_actionability":"action","recommended_fix_focus":"fix","summary":"summary","related_ids":["app-api-123","fic-1","sp-api-123"]},{"row_class":"existing_credential","target_object_type":"Application","target_object_id":"app-dev-123","target_object_name":"ho-viewpoint-dev","backing_service_principal_id":"sp-dev-123","backing_service_principal_name":"ho-viewpoint-dev","credential_type":"password","control_path":"existing-auth-material","role_context":"role context","tenant_context":"current-tenant","current_evidence":"evidence","missing_proof":"proof","operator_actionability":"action","recommended_fix_focus":"fix","summary":"summary","related_ids":["app-dev-123","sp-dev-123"]}],"issues":[],"metadata":{"command":"app-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-credentials-context.json"), liveAppCredentialsContextArtifact{
		OwnedApplications: []liveAppCredentialApplicationTruth{{
			ObjectID:                    "app-api-123",
			DisplayName:                 "ho-roletrust-api",
			BackingServicePrincipalID:   "sp-api-123",
			BackingServicePrincipalName: "ho-roletrust-api",
		}},
		OwnedServicePrincipals: []liveAppCredentialServicePrincipalTruth{{
			ObjectID:    "sp-api-123",
			DisplayName: "ho-roletrust-api",
		}},
		ExistingFederatedApplications: []liveAppCredentialApplicationTruth{{
			ObjectID:                    "app-api-123",
			DisplayName:                 "ho-roletrust-api",
			BackingServicePrincipalID:   "sp-api-123",
			BackingServicePrincipalName: "ho-roletrust-api",
		}},
		ExistingCredentialApplications: []liveAppCredentialExistingCredential{{
			ObjectID:                    "app-dev-123",
			DisplayName:                 "ho-viewpoint-dev",
			BackingServicePrincipalID:   "sp-dev-123",
			BackingServicePrincipalName: "ho-viewpoint-dev",
			CredentialType:              "password",
		}},
	}); err != nil {
		t.Fatalf("write app-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected app-credentials seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsEmptyReducedViewAppCredentials(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-credentials-empty-test",
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
		RunID:      "live-app-credentials-empty-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "app-credentials",
			Viewpoint:   "dev",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/app-credentials/dev/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-credentials", "dev")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_credentials":[],"issues":[],"metadata":{"command":"app-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-credentials-context.json"), liveAppCredentialsContextArtifact{
		ExpectZeroRows: true,
	}); err != nil {
		t.Fatalf("write app-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected empty reduced-view app-credentials seam to pass, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingAppCredentialCanaryRow(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-credentials-drift-test",
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
		RunID:      "live-app-credentials-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "app-credentials",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/app-credentials/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-credentials", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_credentials":[],"issues":[],"metadata":{"command":"app-credentials","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-credentials-context.json"), liveAppCredentialsContextArtifact{
		OwnedApplications: []liveAppCredentialApplicationTruth{{
			ObjectID:                    "app-api-123",
			DisplayName:                 "ho-roletrust-api",
			BackingServicePrincipalID:   "sp-api-123",
			BackingServicePrincipalName: "ho-roletrust-api",
		}},
	}); err != nil {
		t.Fatalf("write app-credentials context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected app-credentials drift finding, got %#v", summary.Findings)
	}
}

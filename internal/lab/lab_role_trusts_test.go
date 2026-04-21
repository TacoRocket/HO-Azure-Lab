package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateLiveRunAcceptsRoleTrustCanaryRows(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-role-trusts-pass-test",
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
		RunID:      "live-role-trusts-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "role-trusts",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/role-trusts/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "role-trusts", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"mode":"fast","trusts":[{"trust_type":"federated-credential","source_object_id":"app-api-123","source_type":"Application","target_object_id":"sp-api-123","target_type":"ServicePrincipal","evidence_type":"graph-federated-credential","confidence":"confirmed","control_primitive":"existing-federated-credential","summary":"issuer https://token.actions.githubusercontent.com subject repo:TacoRocket/HO-Azure:ref:refs/heads/main","related_ids":["app-api-123","fic-123","sp-api-123"]},{"trust_type":"app-owner","source_object_id":"owner-123","source_type":"User","target_object_id":"app-api-123","target_type":"Application","evidence_type":"graph-owner","confidence":"confirmed","control_primitive":"change-auth-material","summary":"summary","related_ids":["owner-123","app-api-123"]},{"trust_type":"service-principal-owner","source_object_id":"owner-123","source_type":"User","target_object_id":"sp-api-123","target_type":"ServicePrincipal","evidence_type":"graph-owner","confidence":"confirmed","control_primitive":"owner-control","summary":"summary","related_ids":["owner-123","sp-api-123"]},{"trust_type":"app-to-service-principal","source_object_id":"sp-client-123","source_type":"ServicePrincipal","target_object_id":"sp-api-123","target_type":"ServicePrincipal","evidence_type":"graph-app-role-assignment","confidence":"confirmed","control_primitive":"existing-app-role-assignment","summary":"summary","related_ids":["sp-client-123","assignment-123","sp-api-123"]}],"issues":[],"metadata":{"command":"role-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-role-trusts-context.json"), liveRoleTrustsContextArtifact{
		ExpectedTrusts: []liveRoleTrustTruth{
			{
				TrustType:        "federated-credential",
				SourceObjectID:   "app-api-123",
				SourceType:       "Application",
				TargetObjectID:   "sp-api-123",
				TargetType:       "ServicePrincipal",
				EvidenceType:     "graph-federated-credential",
				Confidence:       "confirmed",
				ControlPrimitive: "existing-federated-credential",
				SummaryContains:  []string{"https://token.actions.githubusercontent.com", "repo:TacoRocket/HO-Azure:ref:refs/heads/main"},
				RelatedIDs:       []string{"app-api-123", "fic-123", "sp-api-123"},
			},
			{
				TrustType:        "app-owner",
				SourceObjectID:   "owner-123",
				SourceType:       "User",
				TargetObjectID:   "app-api-123",
				TargetType:       "Application",
				EvidenceType:     "graph-owner",
				Confidence:       "confirmed",
				ControlPrimitive: "change-auth-material",
				RelatedIDs:       []string{"owner-123", "app-api-123"},
			},
			{
				TrustType:        "service-principal-owner",
				SourceObjectID:   "owner-123",
				SourceType:       "User",
				TargetObjectID:   "sp-api-123",
				TargetType:       "ServicePrincipal",
				EvidenceType:     "graph-owner",
				Confidence:       "confirmed",
				ControlPrimitive: "owner-control",
				RelatedIDs:       []string{"owner-123", "sp-api-123"},
			},
			{
				TrustType:        "app-to-service-principal",
				SourceObjectID:   "sp-client-123",
				SourceType:       "ServicePrincipal",
				TargetObjectID:   "sp-api-123",
				TargetType:       "ServicePrincipal",
				EvidenceType:     "graph-app-role-assignment",
				Confidence:       "confirmed",
				ControlPrimitive: "existing-app-role-assignment",
				RelatedIDs:       []string{"sp-client-123", "assignment-123", "sp-api-123"},
			},
		},
	}); err != nil {
		t.Fatalf("write role-trusts context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected role-trusts seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsUnreadableReducedRoleTrusts(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-role-trusts-reduced-test",
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
		RunID:      "live-role-trusts-reduced-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "role-trusts",
			Viewpoint:   "dev",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/role-trusts/dev/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "role-trusts", "dev")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"mode":"fast","trusts":[],"issues":[{"kind":"collection_error","scope":"role_trusts.service_principals","message":"blocked","context":{"collector":"role_trusts.service_principals"}}],"metadata":{"command":"role-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-role-trusts-context.json"), liveRoleTrustsContextArtifact{
		ExpectZeroRows:          true,
		RequiredIssueCollectors: []string{"role_trusts.service_principals"},
	}); err != nil {
		t.Fatalf("write role-trusts context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected reduced role-trusts seam to pass, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingRoleTrustRow(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-role-trusts-drift-test",
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
		RunID:      "live-role-trusts-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "role-trusts",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/role-trusts/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "role-trusts", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"mode":"fast","trusts":[{"trust_type":"federated-credential","source_object_id":"app-api-123","source_type":"Application","target_object_id":"sp-api-123","target_type":"ServicePrincipal","evidence_type":"graph-federated-credential","confidence":"confirmed","control_primitive":"existing-federated-credential","summary":"issuer https://token.actions.githubusercontent.com subject repo:TacoRocket/HO-Azure:ref:refs/heads/main","related_ids":["app-api-123","fic-123","sp-api-123"]}],"issues":[],"metadata":{"command":"role-trusts","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-role-trusts-context.json"), liveRoleTrustsContextArtifact{
		ExpectedTrusts: []liveRoleTrustTruth{{
			TrustType:        "app-to-service-principal",
			SourceObjectID:   "sp-client-123",
			SourceType:       "ServicePrincipal",
			TargetObjectID:   "sp-api-123",
			TargetType:       "ServicePrincipal",
			EvidenceType:     "graph-app-role-assignment",
			Confidence:       "confirmed",
			ControlPrimitive: "existing-app-role-assignment",
			RelatedIDs:       []string{"sp-client-123", "assignment-123", "sp-api-123"},
		}},
	}); err != nil {
		t.Fatalf("write role-trusts context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected role-trusts drift finding, got %#v", summary.Findings)
	}
}

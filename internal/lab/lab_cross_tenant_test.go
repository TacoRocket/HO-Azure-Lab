package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateLiveRunAcceptsCrossTenantEvidenceRows(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-cross-tenant-pass-test",
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
		RunID:      "live-cross-tenant-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "cross-tenant",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/cross-tenant/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "cross-tenant", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"cross_tenant_paths":[{"attack_path":"entry","id":"authorizationPolicy","name":"Authorization Policy","posture":"guest-invites=everyone; app-registration=yes; user-consent=self-service","priority":"high","related_ids":["authorizationPolicy"],"scope":"tenant","signal_type":"policy","summary":"summary","tenant_id":"tenant-123","tenant_name":null},{"attack_path":"pivot","id":"sp-ext-1","name":"AAD App Management","posture":"roles=none-visible; assignments=0; scopes=0","priority":"low","related_ids":["sp-ext-1"],"scope":"tenant","signal_type":"external-sp","summary":"summary","tenant_id":"tenant-external","tenant_name":null}],"findings":[],"issues":[{"kind":"collection_error","scope":"auth_policies.security_defaults","message":"blocked","context":{"collector":"auth_policies.security_defaults"}}],"metadata":{"command":"cross-tenant","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-cross-tenant-context.json"), liveCrossTenantContextArtifact{
		ExpectedRows: []liveCrossTenantRowTruth{
			{
				AttackPath: "entry",
				ID:         "authorizationPolicy",
				Name:       "Authorization Policy",
				Priority:   "high",
				RelatedIDs: []string{"authorizationPolicy"},
				Scope:      "tenant",
				SignalType: "policy",
				TenantID:   "tenant-123",
			},
			{
				AttackPath: "pivot",
				ID:         "sp-ext-1",
				Name:       "AAD App Management",
				Priority:   "low",
				RelatedIDs: []string{"sp-ext-1"},
				Scope:      "tenant",
				SignalType: "external-sp",
				TenantID:   "tenant-external",
			},
		},
		RequiredIssueCollectors: []string{"auth_policies.security_defaults"},
	}); err != nil {
		t.Fatalf("write cross-tenant context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected cross-tenant seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsUnreadableReducedCrossTenant(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-cross-tenant-reduced-test",
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
		RunID:      "live-cross-tenant-reduced-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "cross-tenant",
			Viewpoint:   "dev",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/cross-tenant/dev/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "cross-tenant", "dev")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"cross_tenant_paths":[],"findings":[],"issues":[{"kind":"collection_error","scope":"auth_policies.security_defaults","message":"blocked","context":{"collector":"auth_policies.security_defaults"}},{"kind":"collection_error","scope":"auth_policies.authorization_policy","message":"blocked","context":{"collector":"auth_policies.authorization_policy"}},{"kind":"collection_error","scope":"auth_policies.conditional_access","message":"blocked","context":{"collector":"auth_policies.conditional_access"}},{"kind":"collection_error","scope":"cross_tenant.service_principals","message":"blocked","context":{"collector":"cross_tenant.service_principals"}}],"metadata":{"command":"cross-tenant","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-cross-tenant-context.json"), liveCrossTenantContextArtifact{
		RequiredIssueCollectors: []string{
			"auth_policies.security_defaults",
			"auth_policies.authorization_policy",
			"auth_policies.conditional_access",
			"cross_tenant.service_principals",
		},
	}); err != nil {
		t.Fatalf("write cross-tenant context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected reduced cross-tenant seam to pass, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingCrossTenantIssue(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-cross-tenant-drift-test",
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
		RunID:      "live-cross-tenant-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "cross-tenant",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/cross-tenant/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "cross-tenant", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"cross_tenant_paths":[{"attack_path":"entry","id":"authorizationPolicy","name":"Authorization Policy","priority":"high","related_ids":["authorizationPolicy"],"scope":"tenant","signal_type":"policy","summary":"summary","tenant_id":"tenant-123","tenant_name":null}],"findings":[],"issues":[],"metadata":{"command":"cross-tenant","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-cross-tenant-context.json"), liveCrossTenantContextArtifact{
		ExpectedRows: []liveCrossTenantRowTruth{{
			AttackPath: "entry",
			ID:         "authorizationPolicy",
			Name:       "Authorization Policy",
			Priority:   "high",
			RelatedIDs: []string{"authorizationPolicy"},
			Scope:      "tenant",
			SignalType: "policy",
			TenantID:   "tenant-123",
		}},
		RequiredIssueCollectors: []string{"auth_policies.security_defaults"},
	}); err != nil {
		t.Fatalf("write cross-tenant context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected cross-tenant drift finding, got %#v", summary.Findings)
	}
}

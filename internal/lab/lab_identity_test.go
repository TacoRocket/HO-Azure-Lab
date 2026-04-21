package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunFlagsWhoAmIPrincipalsTypeDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-principal-drift-test",
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
		RunID:      "live-principal-drift-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "principals",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/principals/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	principalsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "principals", "admin")
	if err := os.MkdirAll(principalsDir, 0o755); err != nil {
		t.Fatalf("mkdir principals dir: %v", err)
	}
	principalsPayload := `{"principals":[{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"ServicePrincipal"}],"issues":[],"metadata":{"command":"principals","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(principalsDir, "stdout.json"), []byte(principalsPayload), 0o644); err != nil {
		t.Fatalf("write principals payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/principals drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "reports principal_type") && strings.Contains(finding.Summary, "principals") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/principals principal_type drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWhoAmIPrincipalsCurrentIdentityDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-principals-current-identity-test",
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
		RunID:      "live-principals-current-identity-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "principals",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/principals/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ServicePrincipal","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "ServicePrincipal",
		PrincipalName:  "vm-mi-identity",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	principalsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "principals", "admin")
	if err := os.MkdirAll(principalsDir, 0o755); err != nil {
		t.Fatalf("mkdir principals dir: %v", err)
	}
	principalsPayload := `{"principals":[{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ServicePrincipal","is_current_identity":false,"identity_names":["vm-mi"],"identity_types":["systemAssigned"]}],"issues":[],"metadata":{"command":"principals","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(principalsDir, "stdout.json"), []byte(principalsPayload), 0o644); err != nil {
		t.Fatalf("write principals payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/principals current identity drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not keep it marked as the current identity") && strings.Contains(finding.Summary, "principals") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/principals current identity drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsServicePrincipalCurrentIdentityInPrincipals(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-principals-service-principal-test",
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
		RunID:      "live-principals-service-principal-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "principals",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/principals/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ServicePrincipal","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "ServicePrincipal",
		PrincipalName:  "vm-mi-identity",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	principalsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "principals", "admin")
	if err := os.MkdirAll(principalsDir, 0o755); err != nil {
		t.Fatalf("mkdir principals dir: %v", err)
	}
	principalsPayload := `{"principals":[{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ServicePrincipal","is_current_identity":true,"identity_names":["vm-mi"],"identity_types":["systemAssigned"]}],"issues":[],"metadata":{"command":"principals","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(principalsDir, "stdout.json"), []byte(principalsPayload), 0o644); err != nil {
		t.Fatalf("write principals payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected no findings for service-principal current identity, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWhoAmIPermissionsCurrentIdentityDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-permissions-drift-test",
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
		RunID:      "live-permissions-drift-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "permissions",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/permissions/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	permissionsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "permissions", "admin")
	if err := os.MkdirAll(permissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir permissions dir: %v", err)
	}
	permissionsPayload := `{"permissions":[{"principal_id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","priority":"high","high_impact_roles":["Reader"],"all_role_names":["Reader"],"role_assignment_count":1,"scope_count":1,"scope_ids":["/subscriptions/sub-123"],"privileged":false,"is_current_identity":false,"operator_signal":"visible","next_review":"review","summary":"summary"}],"issues":[],"metadata":{"command":"permissions","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(permissionsDir, "stdout.json"), []byte(permissionsPayload), 0o644); err != nil {
		t.Fatalf("write permissions payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/permissions drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not keep it marked as the current identity") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/permissions current identity drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWhoAmIRbacPrincipalVisibilityDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-rbac-visibility-test",
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
		RunID:      "live-rbac-visibility-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "rbac",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/rbac/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	rbacDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "rbac", "admin")
	if err := os.MkdirAll(rbacDir, 0o755); err != nil {
		t.Fatalf("mkdir rbac dir: %v", err)
	}
	rbacPayload := `{"principals":[],"role_assignments":[],"issues":[],"metadata":{"command":"rbac","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"},"scopes":[]}`
	if err := os.WriteFile(filepath.Join(rbacDir, "stdout.json"), []byte(rbacPayload), 0o644); err != nil {
		t.Fatalf("write rbac payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/rbac drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not keep that principal visible in its principals list") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/rbac principal visibility drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWhoAmIRbacPrincipalTypeDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-rbac-type-drift-test",
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
		RunID:      "live-rbac-type-drift-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "rbac",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/rbac/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	rbacDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "rbac", "admin")
	if err := os.MkdirAll(rbacDir, 0o755); err != nil {
		t.Fatalf("mkdir rbac dir: %v", err)
	}
	rbacPayload := `{"principals":[{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"ServicePrincipal","tenant_id":"tenant-123"}],"role_assignments":[{"id":"ra-1","principal_id":"actual-principal-123","principal_type":"ServicePrincipal","role_definition_id":"rd-owner","role_name":"Owner","scope_id":"/subscriptions/sub-123"}],"issues":[],"metadata":{"command":"rbac","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"},"scopes":[]}`
	if err := os.WriteFile(filepath.Join(rbacDir, "stdout.json"), []byte(rbacPayload), 0o644); err != nil {
		t.Fatalf("write rbac payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/rbac type drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "reports principal_type") && strings.Contains(finding.Summary, "commands rbac") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/rbac principal_type drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsManagedIdentityEquivalentRbacPrincipalType(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-rbac-managed-identity-equivalence-test",
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
		RunID:      "live-rbac-managed-identity-equivalence-test",
		EntryCount: 2,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "rbac",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/rbac/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ManagedIdentity","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "ServicePrincipal",
		PrincipalName:  "vm-mi-identity",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	rbacDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "rbac", "admin")
	if err := os.MkdirAll(rbacDir, 0o755); err != nil {
		t.Fatalf("mkdir rbac dir: %v", err)
	}
	rbacPayload := `{"principals":[{"id":"actual-principal-123","display_name":"vm-mi-identity","principal_type":"ServicePrincipal","tenant_id":"tenant-123"}],"role_assignments":[{"id":"ra-1","principal_id":"actual-principal-123","principal_type":"ServicePrincipal","role_definition_id":"rd-owner","role_name":"Contributor","scope_id":"/subscriptions/sub-123/resourceGroups/rg-workload"}],"issues":[],"metadata":{"command":"rbac","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"},"scopes":[]}`
	if err := os.WriteFile(filepath.Join(rbacDir, "stdout.json"), []byte(rbacPayload), 0o644); err != nil {
		t.Fatalf("write rbac payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected no findings for managed-identity/service-principal equivalence, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWhoAmIPrivescCurrentPathMissing(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-privesc-missing-test",
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
		RunID:      "live-privesc-missing-test",
		EntryCount: 3,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "permissions",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/permissions/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "privesc",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/privesc/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	permissionsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "permissions", "admin")
	if err := os.MkdirAll(permissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir permissions dir: %v", err)
	}
	permissionsPayload := `{"permissions":[{"principal_id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","priority":"high","high_impact_roles":["Owner"],"all_role_names":["Owner"],"role_assignment_count":2,"scope_count":1,"scope_ids":["/subscriptions/sub-123"],"privileged":true,"is_current_identity":true,"operator_signal":"visible","next_review":"review","summary":"summary"}],"issues":[],"metadata":{"command":"permissions","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(permissionsDir, "stdout.json"), []byte(permissionsPayload), 0o644); err != nil {
		t.Fatalf("write permissions payload: %v", err)
	}

	privescDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "privesc", "admin")
	if err := os.MkdirAll(privescDir, 0o755); err != nil {
		t.Fatalf("mkdir privesc dir: %v", err)
	}
	privescPayload := `{"paths":[],"issues":[],"metadata":{"command":"privesc","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(privescDir, "stdout.json"), []byte(privescPayload), 0o644); err != nil {
		t.Fatalf("write privesc payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected whoami/privesc finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not return a current-foothold-direct-control path") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected whoami/privesc missing current path finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsMatchingWhoAmIPrivescCurrentPath(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-privesc-match-test",
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
		RunID:      "live-privesc-match-test",
		EntryCount: 3,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "permissions",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/permissions/admin/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "privesc",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/privesc/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	permissionsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "permissions", "admin")
	if err := os.MkdirAll(permissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir permissions dir: %v", err)
	}
	permissionsPayload := `{"permissions":[{"principal_id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","priority":"high","high_impact_roles":["Owner"],"all_role_names":["Owner"],"role_assignment_count":2,"scope_count":1,"scope_ids":["/subscriptions/sub-123"],"privileged":true,"is_current_identity":true,"operator_signal":"visible","next_review":"review","summary":"summary"}],"issues":[],"metadata":{"command":"permissions","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(permissionsDir, "stdout.json"), []byte(permissionsPayload), 0o644); err != nil {
		t.Fatalf("write permissions payload: %v", err)
	}

	privescDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "privesc", "admin")
	if err := os.MkdirAll(privescDir, 0o755); err != nil {
		t.Fatalf("mkdir privesc dir: %v", err)
	}
	privescPayload := `{"paths":[{"asset":null,"current_identity":true,"impact_roles":["Owner"],"starting_foothold":"Colby Farley (current foothold)","missing_proof":"not proved","next_review":"review","operator_signal":"Current foothold already has direct control.","path_type":"current-foothold-direct-control","target":"current foothold (user)","preferred":true,"preferred_reason":"Preferred foothold","priority":"high","principal":"Colby Farley","principal_id":"actual-principal-123","principal_type":"User","proven_path":"Current foothold already holds high-impact RBAC.","related_ids":["actual-principal-123","/subscriptions/sub-123"],"summary":"summary"}],"issues":[],"metadata":{"command":"privesc","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(privescDir, "stdout.json"), []byte(privescPayload), 0o644); err != nil {
		t.Fatalf("write privesc payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected matching whoami/privesc seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsNonPrivilegedCurrentIdentityPrivescPath(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-privesc-non-privileged-drift-test",
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
		RunID:      "live-privesc-non-privileged-drift-test",
		EntryCount: 3,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/lower-privilege/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "permissions",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/permissions/lower-privilege/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "privesc",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/privesc/lower-privilege/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "lower-privilege")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"HOuser734630445446","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "HOuser734630445446",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	permissionsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "permissions", "lower-privilege")
	if err := os.MkdirAll(permissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir permissions dir: %v", err)
	}
	permissionsPayload := `{"permissions":[{"principal_id":"actual-principal-123","display_name":"HOuser734630445446","principal_type":"User","priority":"low","high_impact_roles":["Reader"],"all_role_names":["Reader"],"role_assignment_count":1,"scope_count":1,"scope_ids":["/subscriptions/sub-123/resourceGroups/rg-workload"],"privileged":false,"is_current_identity":true,"operator_signal":"visible","next_review":"review","summary":"summary"}],"issues":[],"metadata":{"command":"permissions","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(permissionsDir, "stdout.json"), []byte(permissionsPayload), 0o644); err != nil {
		t.Fatalf("write permissions payload: %v", err)
	}

	privescDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "privesc", "lower-privilege")
	if err := os.MkdirAll(privescDir, 0o755); err != nil {
		t.Fatalf("mkdir privesc dir: %v", err)
	}
	privescPayload := `{"paths":[{"asset":null,"current_identity":true,"impact_roles":["Reader"],"starting_foothold":"HOuser734630445446 (current foothold)","missing_proof":"not proved","next_review":"review","operator_signal":"Current foothold already has direct control.","path_type":"current-foothold-direct-control","target":"current foothold (user)","preferred":true,"preferred_reason":"Preferred foothold","priority":"high","principal":"HOuser734630445446","principal_id":"actual-principal-123","principal_type":"User","proven_path":"Current foothold already holds visible RBAC.","related_ids":["actual-principal-123","/subscriptions/sub-123/resourceGroups/rg-workload"],"summary":"summary"}],"issues":[],"metadata":{"command":"privesc","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(privescDir, "stdout.json"), []byte(privescPayload), 0o644); err != nil {
		t.Fatalf("write privesc payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected non-privileged whoami/privesc finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "marks principal.id \"actual-principal-123\" as not privileged") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected non-privileged current path finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsNonPrivilegedVisibleLeadOnlyPrivesc(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-privesc-non-privileged-visible-lead-test",
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
		RunID:      "live-privesc-non-privileged-visible-lead-test",
		EntryCount: 3,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/lower-privilege/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "permissions",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/permissions/lower-privilege/stdout.json",
			},
			{
				SurfaceKind: "commands",
				SurfaceName: "privesc",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/privesc/lower-privilege/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	whoamiDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "lower-privilege")
	if err := os.MkdirAll(whoamiDir, 0o755); err != nil {
		t.Fatalf("mkdir whoami dir: %v", err)
	}
	whoamiPayload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"HOuser734630445446","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(whoamiDir, "stdout.json"), []byte(whoamiPayload), 0o644); err != nil {
		t.Fatalf("write whoami payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(whoamiDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "HOuser734630445446",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	permissionsDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "permissions", "lower-privilege")
	if err := os.MkdirAll(permissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir permissions dir: %v", err)
	}
	permissionsPayload := `{"permissions":[{"principal_id":"actual-principal-123","display_name":"HOuser734630445446","principal_type":"User","priority":"low","high_impact_roles":["Reader"],"all_role_names":["Reader"],"role_assignment_count":1,"scope_count":1,"scope_ids":["/subscriptions/sub-123/resourceGroups/rg-workload"],"privileged":false,"is_current_identity":true,"operator_signal":"visible","next_review":"review","summary":"summary"}],"issues":[],"metadata":{"command":"permissions","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(permissionsDir, "stdout.json"), []byte(permissionsPayload), 0o644); err != nil {
		t.Fatalf("write permissions payload: %v", err)
	}

	privescDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "privesc", "lower-privilege")
	if err := os.MkdirAll(privescDir, 0o755); err != nil {
		t.Fatalf("mkdir privesc dir: %v", err)
	}
	privescPayload := `{"paths":[{"asset":null,"current_identity":false,"impact_roles":["Contributor"],"starting_foothold":"HOuser734630445446 (current foothold)","missing_proof":"not proved","next_review":"review","operator_signal":"Visible privileged lead; not yet rooted in current foothold.","path_type":"visible-privileged-lead","target":"visible privileged principal","preferred":true,"preferred_reason":"Preferred foothold","priority":"medium","principal":"HOdev734630445446","principal_id":"visible-principal-456","principal_type":"User","proven_path":"Visible privileged identity already has direct control.","related_ids":["visible-principal-456","/subscriptions/sub-123/resourceGroups/rg-workload"],"summary":"summary"}],"issues":[],"metadata":{"command":"privesc","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(privescDir, "stdout.json"), []byte(privescPayload), 0o644); err != nil {
		t.Fatalf("write privesc payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected non-privileged visible-lead-only privesc seam to pass cleanly, got %#v", summary.Findings)
	}
}

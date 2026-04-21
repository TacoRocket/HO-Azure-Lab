package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGraphReadDeniedRecognizesAuthPoliciesAccessDeniedShapes(t *testing.T) {
	cases := [][]byte{
		[]byte(`ERROR: Forbidden({"error":{"code":"AccessDenied","message":"You cannot perform the requested operation, required scopes are missing in the token."}})`),
		[]byte(`ERROR: Forbidden({"error":{"code":"AccessDenied","message":"Applications without a signed-in user are not allowed access to this report or data."}})`),
	}
	for _, payload := range cases {
		if !graphReadDenied(payload) {
			t.Fatalf("expected graphReadDenied to classify %q as read denied", string(payload))
		}
	}
}

func TestValidateLiveRunAcceptsVisibleAuthPolicies(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-auth-policies-pass-test",
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
		RunID:      "live-auth-policies-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "auth-policies",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/auth-policies/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "auth-policies", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"auth_policies":[{"controls":["guest-invites:everyone","sspr:enabled","users-can-register-apps","users-can-create-security-groups","user-consent:self-service"],"name":"Authorization Policy","policy_type":"authorization-policy","related_ids":["authorizationPolicy"],"scope":"tenant","state":"configured","summary":"guest invites: everyone; users can register apps; self-service permission grant policies assigned"}],"findings":[{"id":"auth-policy-users-can-register-apps"},{"id":"auth-policy-guest-invites-everyone"},{"id":"auth-policy-user-consent-enabled"}],"issues":[{"kind":"collection_error","scope":"auth_policies.security_defaults","message":"blocked","context":{"collector":"auth_policies.security_defaults"}}],"metadata":{"command":"auth-policies","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-auth-policies-context.json"), liveAuthPoliciesContextArtifact{
		VisiblePolicies: []liveAuthPolicyTruth{{
			Controls:   []string{"guest-invites:everyone", "sspr:enabled", "users-can-register-apps", "users-can-create-security-groups", "user-consent:self-service"},
			Name:       "Authorization Policy",
			PolicyType: "authorization-policy",
			RelatedIDs: []string{"authorizationPolicy"},
			Scope:      "tenant",
			State:      "configured",
		}},
		RequiredIssueCollectors: []string{"auth_policies.security_defaults"},
	}); err != nil {
		t.Fatalf("write auth-policies context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected auth-policies seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsUnreadableReducedAuthPolicies(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-auth-policies-reduced-test",
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
		RunID:      "live-auth-policies-reduced-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "auth-policies",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/auth-policies/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "auth-policies", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"auth_policies":[],"findings":[],"issues":[{"kind":"collection_error","scope":"auth_policies.security_defaults","message":"blocked","context":{"collector":"auth_policies.security_defaults"}},{"kind":"collection_error","scope":"auth_policies.authorization_policy","message":"blocked","context":{"collector":"auth_policies.authorization_policy"}},{"kind":"collection_error","scope":"auth_policies.conditional_access","message":"blocked","context":{"collector":"auth_policies.conditional_access"}}],"metadata":{"command":"auth-policies","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-auth-policies-context.json"), liveAuthPoliciesContextArtifact{
		RequiredIssueCollectors: []string{
			"auth_policies.security_defaults",
			"auth_policies.authorization_policy",
			"auth_policies.conditional_access",
		},
	}); err != nil {
		t.Fatalf("write auth-policies context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected unreadable reduced auth-policies seam to pass, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsMissingAuthPolicyIssue(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-auth-policies-drift-test",
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
		RunID:      "live-auth-policies-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "auth-policies",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/auth-policies/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "auth-policies", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"auth_policies":[{"controls":["guest-invites:everyone","users-can-register-apps","user-consent:self-service"],"name":"Authorization Policy","policy_type":"authorization-policy","related_ids":["authorizationPolicy"],"scope":"tenant","state":"configured"}],"findings":[{"id":"auth-policy-users-can-register-apps"},{"id":"auth-policy-guest-invites-everyone"},{"id":"auth-policy-user-consent-enabled"}],"issues":[],"metadata":{"command":"auth-policies","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-auth-policies-context.json"), liveAuthPoliciesContextArtifact{
		VisiblePolicies: []liveAuthPolicyTruth{{
			Controls:   []string{"guest-invites:everyone", "users-can-register-apps", "user-consent:self-service"},
			Name:       "Authorization Policy",
			PolicyType: "authorization-policy",
			RelatedIDs: []string{"authorizationPolicy"},
			Scope:      "tenant",
			State:      "configured",
		}},
		RequiredIssueCollectors: []string{"auth_policies.security_defaults"},
	}); err != nil {
		t.Fatalf("write auth-policies context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected auth-policies drift finding, got %#v", summary.Findings)
	}
}

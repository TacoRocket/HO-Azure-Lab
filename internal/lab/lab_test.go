package lab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

var hoAzureDir = resolveTestHOAzureDir()

func resolveTestHOAzureDir() string {
	if configured := strings.TrimSpace(os.Getenv("HO_AZURE_TEST_DIR")); configured != "" {
		return configured
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("internal", "lab", "testdata", "ho-azure")
	}
	return filepath.Join(filepath.Dir(currentFile), "testdata", "ho-azure")
}

func TestDeriveSurfaceIncludesContractsAndGroups(t *testing.T) {
	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		t.Fatalf("derive surface: %v", err)
	}

	if !slices.Contains(surface.Commands, "whoami") {
		t.Fatalf("expected whoami in commands: %#v", surface.Commands)
	}
	if !slices.Contains(surface.Families, "credential-path") {
		t.Fatalf("expected credential-path in families: %#v", surface.Families)
	}
	if surface.FamilyGroupCommands["credential-path"] != "chains" {
		t.Fatalf("expected credential-path to use chains, got %q", surface.FamilyGroupCommands["credential-path"])
	}
	fields := surface.CommandTopLevelFields["whoami"]
	if !slices.Contains(fields, "metadata") || !slices.Contains(fields, "issues") {
		t.Fatalf("expected whoami fields to include metadata and issues: %#v", fields)
	}
}

func TestTruthFirstBootstrapManifestTracksCoveredAndExceptedSurfaces(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "truth-first-bootstrap")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}

	if manifest.Surfaces.Commands["whoami"].Status != "covered" {
		t.Fatalf("expected whoami to be covered, got %q", manifest.Surfaces.Commands["whoami"].Status)
	}
	if manifest.Surfaces.Commands["devops"].ReasonCode != "manual_setup_not_done" {
		t.Fatalf("expected devops manual setup exception, got %#v", manifest.Surfaces.Commands["devops"])
	}
	if manifest.Surfaces.Commands["app-credentials"].Status != "covered" {
		t.Fatalf("expected app-credentials to be covered, got %#v", manifest.Surfaces.Commands["app-credentials"])
	}
	if manifest.Surfaces.Families["compute-control"].Status != "covered" {
		t.Fatalf("expected compute-control to be covered, got %#v", manifest.Surfaces.Families["compute-control"])
	}
}

func TestScaffoldRunBuildsScopeAndArtifacts(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "truth-first-bootstrap")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}
	outputDir := t.TempDir()

	runResult, err := ScaffoldRun(manifest, outputDir, "bootstrap-run", true)
	if err != nil {
		t.Fatalf("scaffold run: %v", err)
	}

	if runResult.FinalOutcome != "blocked" {
		t.Fatalf("expected blocked scaffold outcome, got %q", runResult.FinalOutcome)
	}
	if !slices.Contains(runResult.Scope.Commands.Covered, "whoami") {
		t.Fatalf("expected whoami in covered scope: %#v", runResult.Scope.Commands.Covered)
	}
	if !slices.Contains(runResult.Scope.Commands.ExceptedByReason["manual_setup_not_done"], "devops") {
		t.Fatalf("expected devops in manual setup bucket: %#v", runResult.Scope.Commands.ExceptedByReason)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "command-log.json")); err != nil {
		t.Fatalf("expected command-log scaffold artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "demo", "index.json")); err != nil {
		t.Fatalf("expected demo scaffold artifact: %v", err)
	}
}

func TestValidateLabFailsWhenManifestMissesShippedSurface(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "truth-first-bootstrap")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}
	delete(manifest.Surfaces.Commands, "whoami")

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := WriteJSON(manifestPath, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	summary, err := ValidateLab(manifestPath, hoAzureDir, "")
	if err != nil {
		t.Fatalf("validate lab: %v", err)
	}
	if summary.CompletionStatus != "incomplete" {
		t.Fatalf("expected incomplete summary, got %#v", summary)
	}
	found := false
	for _, failure := range summary.AutomaticFailures {
		if strings.Contains(failure, "manifest is missing commands: whoami") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected missing whoami failure, got %#v", summary.AutomaticFailures)
	}
}

func TestBuildSurfacePlanAndInvocationStayTruthFirst(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "truth-first-bootstrap")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}
	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		t.Fatalf("derive surface: %v", err)
	}

	tasks := BuildSurfacePlan(manifest, surface, []string{"admin"})
	commandSurfaces := []string{}
	familySurfaces := []string{}
	for _, task := range tasks {
		if task.SurfaceKind == "commands" {
			commandSurfaces = append(commandSurfaces, task.SurfaceName)
		} else {
			familySurfaces = append(familySurfaces, task.SurfaceName)
		}
	}

	if !slices.Contains(commandSurfaces, "whoami") || slices.Contains(commandSurfaces, "devops") {
		t.Fatalf("unexpected command plan split: %#v", commandSurfaces)
	}
	if !slices.Contains(familySurfaces, "credential-path") || !slices.Contains(familySurfaces, "compute-control") {
		t.Fatalf("unexpected family plan split: %#v", familySurfaces)
	}

	invocation := BuildInvocation(
		[]string{"go", "run", "./cmd/azurefox"},
		SurfaceTask{
			SurfaceKind:  "families",
			SurfaceName:  "credential-path",
			Viewpoint:    "admin",
			GroupCommand: "chains",
			Subcommand:   "credential-path",
		},
		"/tmp/ho-azure-family-test",
		"tenant-id",
		"subscription-id",
		"",
		"json",
		true,
	)

	expectedPrefix := []string{"go", "run", "./cmd/azurefox", "chains", "credential-path"}
	if !slices.Equal(invocation[:5], expectedPrefix) {
		t.Fatalf("unexpected family invocation prefix: %#v", invocation[:5])
	}
	if !slices.Contains(invocation, "--output") || !slices.Contains(invocation, "json") {
		t.Fatalf("expected json output flags in invocation: %#v", invocation)
	}
	if !slices.Contains(invocation, "--outdir") {
		t.Fatalf("expected outdir in invocation: %#v", invocation)
	}
}

func TestValidateLiveRunFindsMissingContractField(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-test",
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
		RunID:      "live-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}
	payloadPath := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin", "stdout.json")
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err != nil {
		t.Fatalf("mkdir payloads: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"tenant_id":"t","subscription":{},"principal":{},"effective_scopes":[],"issues":[]}`), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected blocking finding, got %#v", summary)
	}
	if !strings.Contains(summary.Findings[0].Summary, "missing contracted top-level fields") {
		t.Fatalf("unexpected finding summary: %#v", summary.Findings[0])
	}
}

func TestValidateLiveRunFlagsMissingLiveAzureContextForWhoAmI(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-missing-context-test",
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
		RunID:      "live-missing-context-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "dev",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/dev/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}
	payloadPath := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "dev", "stdout.json")
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err != nil {
		t.Fatalf("mkdir payloads: %v", err)
	}
	payload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"wrong-principal","display_name":"validator-dev","principal_type":"ServicePrincipal","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(payloadPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected missing live Azure context finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not record a live Azure context artifact") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected missing live Azure context finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunChecksWhoAmIAgainstLiveAzureContextArtifact(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-azure-context-test",
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
		RunID:      "live-azure-context-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}
	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"wrong-principal","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected live Azure context mismatch finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "Azure returned") && strings.Contains(finding.Summary, "principal.id") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Azure-backed principal.id mismatch finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsMatchingWhoAmILiveAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-azure-match-test",
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
		RunID:      "live-azure-match-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "whoami",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/whoami/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}
	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "whoami", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub"},"principal":{"id":"actual-principal-123","display_name":"Colby Farley","principal_type":"User","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-azure-context.json"), liveAzureContextArtifact{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-123",
		PrincipalID:    "actual-principal-123",
		PrincipalType:  "User",
		PrincipalName:  "Colby Farley",
	}); err != nil {
		t.Fatalf("write live azure context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected matching live Azure context to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsManagedIdentityAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-managed-identities-anchor-test",
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
		RunID:      "live-managed-identities-anchor-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "managed-identities",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/managed-identities/lower-privilege/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "managed-identities", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"identities":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app","name":"ua-app","identity_type":"userAssigned","principal_id":"principal-123","client_id":"client-123","attached_to":["/subscriptions/sub-123/resourceGroups/RG-WORKLOAD/providers/Microsoft.Compute/virtualMachines/vm-web-01"],"scope_ids":["/subscriptions/sub-123"],"operator_signal":"Public VM workload pivot; direct control not confirmed.","next_review":"review","summary":"summary"}],"role_assignments":[],"findings":[],"issues":[],"metadata":{"command":"managed-identities","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-managed-identities-context.json"), liveManagedIdentitiesContextArtifact{
		Identities: []liveManagedIdentityTruth{
			{
				DisplayName:  "ua-app",
				PrincipalID:  "principal-123",
				IdentityType: "userAssigned",
				AttachedTo:   []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01"},
			},
		},
	}); err != nil {
		t.Fatalf("write managed identities context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected managed-identity anchor seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsManagedIdentityAttachmentDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-managed-identities-attachment-drift-test",
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
		RunID:      "live-managed-identities-attachment-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "managed-identities",
				Viewpoint:   "lower-privilege",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/managed-identities/lower-privilege/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "managed-identities", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"identities":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app","name":"ua-app","identity_type":"userAssigned","principal_id":"principal-123","client_id":"client-123","attached_to":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders"],"scope_ids":["/subscriptions/sub-123"],"operator_signal":"Internal Function App workload pivot; direct control not confirmed.","next_review":"review","summary":"summary"}],"role_assignments":[],"findings":[],"issues":[],"metadata":{"command":"managed-identities","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-managed-identities-context.json"), liveManagedIdentitiesContextArtifact{
		Identities: []liveManagedIdentityTruth{
			{
				DisplayName:  "ua-app",
				PrincipalID:  "principal-123",
				IdentityType: "userAssigned",
				AttachedTo:   []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01"},
			},
		},
	}); err != nil {
		t.Fatalf("write managed identities context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected managed-identities attachment drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "lost Azure-backed workload attachments for principal_id \"principal-123\"") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected managed-identities attachment drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsWorkloadsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-workloads-context-test",
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
		RunID:      "live-workloads-context-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "workloads",
				Viewpoint:   "dev",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/workloads/dev/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "workloads", "dev")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workloads":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","asset_kind":"VM","asset_name":"vm-web-01","endpoints":["20.1.2.3"],"exposure_families":["public-ip"],"identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"identity_type":"UserAssigned","ingress_paths":["direct-vm-ip"],"location":"centralus","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01"],"resource_group":"rg-workload","summary":"summary"},{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","asset_kind":"FunctionApp","asset_name":"func-orders","endpoints":["func-orders.azurewebsites.net"],"exposure_families":["managed-web-hostname"],"identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"identity_principal_id":"principal-123","identity_type":"SystemAssigned, UserAssigned","ingress_paths":["azure-functions-default-hostname"],"location":"centralus","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders"],"resource_group":"rg-workload","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"workloads","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-workloads-context.json"), liveWorkloadsContextArtifact{
		Workloads: []liveWorkloadTruth{
			{
				AssetID:      "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
				AssetKind:    "VM",
				AssetName:    "vm-web-01",
				IdentityType: "UserAssigned",
				IdentityIDs:  []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
			{
				AssetID:      "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
				AssetKind:    "FunctionApp",
				AssetName:    "func-orders",
				IdentityType: "SystemAssigned, UserAssigned",
				IdentityIDs:  []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
		},
	}); err != nil {
		t.Fatalf("write workloads context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected workloads seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsWorkloadIdentityContextDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-workloads-identity-drift-test",
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
		RunID:      "live-workloads-identity-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "workloads",
				Viewpoint:   "dev",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/workloads/dev/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "workloads", "dev")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workloads":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","asset_kind":"FunctionApp","asset_name":"func-orders","endpoints":["func-orders.azurewebsites.net"],"exposure_families":["managed-web-hostname"],"identity_ids":[],"ingress_paths":["azure-functions-default-hostname"],"location":"centralus","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders"],"resource_group":"rg-workload","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"workloads","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-workloads-context.json"), liveWorkloadsContextArtifact{
		Workloads: []liveWorkloadTruth{
			{
				AssetID:      "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
				AssetKind:    "FunctionApp",
				AssetName:    "func-orders",
				IdentityType: "SystemAssigned, UserAssigned",
				IdentityIDs:  []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
		},
	}); err != nil {
		t.Fatalf("write workloads context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected workloads identity drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "lost the Azure-visible identity context") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected workloads identity-context drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsUnexpectedWorkloadIdentityContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-workloads-unexpected-identity-test",
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
		RunID:      "live-workloads-unexpected-identity-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "workloads",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/workloads/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "workloads", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workloads":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-api","asset_kind":"VMSS","asset_name":"vmss-api","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"identity_type":"UserAssigned","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"workloads","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-workloads-context.json"), liveWorkloadsContextArtifact{
		Workloads: []liveWorkloadTruth{
			{
				AssetID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-api",
				AssetKind: "VMSS",
				AssetName: "vmss-api",
			},
		},
	}); err != nil {
		t.Fatalf("write workloads context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected unexpected workload identity finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "but Azure does not currently show identity on that workload") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected unexpected workload identity finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsAppServicesAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-services-pass-test",
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
		RunID:      "live-app-services-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "app-services",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/app-services/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-services", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_services":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api","name":"app-public-api","default_hostname":"app-public-api.azurewebsites.net","public_network_access":"Enabled","workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"SystemAssigned, UserAssigned","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"app-services","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-services-context.json"), liveAppServicesContextArtifact{
		AppServices: []liveAppServiceTruth{
			{
				ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api",
				Name:                "app-public-api",
				Hostname:            "app-public-api.azurewebsites.net",
				PublicNetworkAccess: "Enabled",
				IdentityType:        "SystemAssigned, UserAssigned",
				IdentityIDs:         []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
		},
	}); err != nil {
		t.Fatalf("write app services context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected app-services seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAppServicesHostnameDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-services-hostname-drift-test",
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
		RunID:      "live-app-services-hostname-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "app-services",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/app-services/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-services", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_services":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api","name":"app-public-api","default_hostname":"wrong.example.net","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"app-services","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-services-context.json"), liveAppServicesContextArtifact{
		AppServices: []liveAppServiceTruth{
			{
				ID:       "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api",
				Name:     "app-public-api",
				Hostname: "app-public-api.azurewebsites.net",
			},
		},
	}); err != nil {
		t.Fatalf("write app services context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected app-services hostname drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "with hostname") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected app-services hostname drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAppServicesPublicNetworkDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-app-services-public-network-drift-test",
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
		RunID:      "live-app-services-public-network-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "app-services",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/app-services/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "app-services", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"app_services":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api","name":"app-public-api","default_hostname":"app-public-api.azurewebsites.net","public_network_access":"Disabled","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"app-services","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-app-services-context.json"), liveAppServicesContextArtifact{
		AppServices: []liveAppServiceTruth{
			{
				ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-public-api",
				Name:                "app-public-api",
				Hostname:            "app-public-api.azurewebsites.net",
				PublicNetworkAccess: "Enabled",
			},
		},
	}); err != nil {
		t.Fatalf("write app services context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected app-services public network drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_network_access") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected app-services public network drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsContainerInstancesAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-container-instances-pass-test",
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
		RunID:      "live-container-instances-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "container-instances",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/container-instances/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "container-instances", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"container_instances":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web","name":"aci-web","public_ip_address":"1.2.3.4","fqdn":"aci-web.centralus.azurecontainer.io","exposed_ports":[80],"restart_policy":"Always","os_type":"Linux","provisioning_state":"Succeeded","container_count":1,"container_images":["mcr.microsoft.com/azuredocs/aci-helloworld:latest"],"subnet_ids":[],"workload_identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"workload_identity_type":"UserAssigned","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"container-instances","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-container-instances-context.json"), liveContainerInstancesContextArtifact{
		ContainerInstances: []liveContainerInstanceTruth{
			{
				ID:                "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
				Name:              "aci-web",
				PublicIPAddress:   "1.2.3.4",
				FQDN:              "aci-web.centralus.azurecontainer.io",
				ExposedPorts:      []int{80},
				RestartPolicy:     "Always",
				OSType:            "Linux",
				ProvisioningState: "Succeeded",
				ContainerCount:    1,
				ContainerImages:   []string{"mcr.microsoft.com/azuredocs/aci-helloworld:latest"},
				SubnetIDs:         []string{},
				IdentityType:      "UserAssigned",
				IdentityIDs:       []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
		},
	}); err != nil {
		t.Fatalf("write container instances context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected container-instances seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsContainerInstancesPublicIPDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-container-instances-public-ip-drift-test",
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
		RunID:      "live-container-instances-public-ip-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "container-instances",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/container-instances/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "container-instances", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"container_instances":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web","name":"aci-web","public_ip_address":"5.6.7.8","fqdn":"aci-web.centralus.azurecontainer.io","exposed_ports":[80],"restart_policy":"Always","os_type":"Linux","provisioning_state":"Succeeded","container_count":1,"container_images":["mcr.microsoft.com/azuredocs/aci-helloworld:latest"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"container-instances","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-container-instances-context.json"), liveContainerInstancesContextArtifact{
		ContainerInstances: []liveContainerInstanceTruth{
			{
				ID:              "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
				Name:            "aci-web",
				PublicIPAddress: "1.2.3.4",
				FQDN:            "aci-web.centralus.azurecontainer.io",
				ExposedPorts:    []int{80},
				RestartPolicy:   "Always",
				OSType:          "Linux",
			},
		},
	}); err != nil {
		t.Fatalf("write container instances context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected container-instances public IP drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_ip_address") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected container-instances public IP drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsAKSAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-aks-pass-test",
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
		RunID:      "live-aks-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "aks",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/aks/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "aks", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"aks_clusters":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerService/managedClusters/aks-ops","name":"aks-ops","resource_group":"rg-workload","location":"centralus","provisioning_state":"Succeeded","kubernetes_version":"1.34","sku_tier":"Free","node_resource_group":"MC_rg-workload_aks-ops_centralus","fqdn":"aks-ops.centralus.azmk8s.io","cluster_identity_type":"SystemAssigned","cluster_principal_id":"principal-123","cluster_identity_ids":[],"local_accounts_disabled":false,"network_plugin":"kubenet","network_policy":"none","outbound_type":"loadBalancer","agent_pool_count":1,"oidc_issuer_enabled":true,"oidc_issuer_url":"https://issuer.example/cluster","addon_names":[],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"aks","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	localAccountsDisabled := false
	agentPoolCount := 1
	oidcIssuerEnabled := true
	if err := WriteJSON(filepath.Join(payloadDir, "live-aks-context.json"), liveAKSContextArtifact{
		AKSClusters: []liveAKSTruth{
			{
				ID:                    "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerService/managedClusters/aks-ops",
				Name:                  "aks-ops",
				ResourceGroup:         "rg-workload",
				Location:              "centralus",
				ProvisioningState:     "Succeeded",
				KubernetesVersion:     "1.34",
				SKUTier:               "Free",
				NodeResourceGroup:     "MC_rg-workload_aks-ops_centralus",
				FQDN:                  "aks-ops.centralus.azmk8s.io",
				ClusterIdentityType:   "SystemAssigned",
				ClusterPrincipalID:    "principal-123",
				ClusterIdentityIDs:    []string{},
				LocalAccountsDisabled: &localAccountsDisabled,
				NetworkPlugin:         "kubenet",
				NetworkPolicy:         "none",
				OutboundType:          "loadBalancer",
				AgentPoolCount:        &agentPoolCount,
				OIDCIssuerEnabled:     &oidcIssuerEnabled,
				OIDCIssuerURL:         "https://issuer.example/cluster",
				AddonNames:            []string{},
			},
		},
	}); err != nil {
		t.Fatalf("write aks context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected aks seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAKSOIDCDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-aks-oidc-drift-test",
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
		RunID:      "live-aks-oidc-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "aks",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/aks/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "aks", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"aks_clusters":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerService/managedClusters/aks-ops","name":"aks-ops","resource_group":"rg-workload","location":"centralus","provisioning_state":"Succeeded","kubernetes_version":"1.34","sku_tier":"Free","node_resource_group":"MC_rg-workload_aks-ops_centralus","fqdn":"aks-ops.centralus.azmk8s.io","cluster_identity_type":"SystemAssigned","cluster_principal_id":"principal-123","cluster_identity_ids":[],"local_accounts_disabled":false,"network_plugin":"kubenet","network_policy":"none","outbound_type":"loadBalancer","agent_pool_count":1,"oidc_issuer_enabled":false,"oidc_issuer_url":"https://issuer.example/cluster","addon_names":[],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"aks","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	localAccountsDisabled := false
	agentPoolCount := 1
	oidcIssuerEnabled := true
	if err := WriteJSON(filepath.Join(payloadDir, "live-aks-context.json"), liveAKSContextArtifact{
		AKSClusters: []liveAKSTruth{
			{
				ID:                    "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerService/managedClusters/aks-ops",
				Name:                  "aks-ops",
				ResourceGroup:         "rg-workload",
				Location:              "centralus",
				ProvisioningState:     "Succeeded",
				KubernetesVersion:     "1.34",
				SKUTier:               "Free",
				NodeResourceGroup:     "MC_rg-workload_aks-ops_centralus",
				FQDN:                  "aks-ops.centralus.azmk8s.io",
				ClusterIdentityType:   "SystemAssigned",
				ClusterPrincipalID:    "principal-123",
				ClusterIdentityIDs:    []string{},
				LocalAccountsDisabled: &localAccountsDisabled,
				NetworkPlugin:         "kubenet",
				NetworkPolicy:         "none",
				OutboundType:          "loadBalancer",
				AgentPoolCount:        &agentPoolCount,
				OIDCIssuerEnabled:     &oidcIssuerEnabled,
				OIDCIssuerURL:         "https://issuer.example/cluster",
				AddonNames:            []string{},
			},
		},
	}); err != nil {
		t.Fatalf("write aks context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected aks oidc drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "oidc_issuer_enabled") && strings.Contains(finding.Summary, "but Azure reports true") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected aks oidc drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsACRAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-acr-pass-test",
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
		RunID:      "live-acr-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "acr",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/acr/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "acr", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"registries":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acr-ops","name":"acr-ops","resource_group":"rg-ops","location":"centralus","state":"Succeeded","login_server":"acr-ops.azurecr.io","sku_name":"Basic","public_network_access":"Enabled","network_rule_bypass_options":"AzureServices","admin_user_enabled":true,"anonymous_pull_enabled":false,"data_endpoint_enabled":false,"private_endpoint_connection_count":0,"webhook_count":0,"enabled_webhook_count":0,"webhook_action_types":[],"broad_webhook_scope_count":0,"replication_count":0,"replication_regions":[],"quarantine_policy_status":"disabled","retention_policy_status":"disabled","retention_policy_days":7,"trust_policy_status":"disabled","trust_policy_type":"notary","workload_identity_type":"SystemAssigned","workload_principal_id":"principal-123","workload_client_id":"client-123","workload_identity_ids":[],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"acr","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	adminUserEnabled := true
	anonymousPullEnabled := false
	dataEndpointEnabled := false
	privateEndpointConnectionCount := 0
	webhookCount := 0
	enabledWebhookCount := 0
	broadWebhookScopeCount := 0
	replicationCount := 0
	retentionPolicyDays := 7
	if err := WriteJSON(filepath.Join(payloadDir, "live-acr-context.json"), liveACRContextArtifact{
		Registries: []liveACRTruth{
			{
				ID:                             "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acr-ops",
				Name:                           "acr-ops",
				ResourceGroup:                  "rg-ops",
				Location:                       "centralus",
				State:                          "Succeeded",
				LoginServer:                    "acr-ops.azurecr.io",
				SKUName:                        "Basic",
				PublicNetworkAccess:            "Enabled",
				NetworkRuleBypassOptions:       "AzureServices",
				AdminUserEnabled:               &adminUserEnabled,
				AnonymousPullEnabled:           &anonymousPullEnabled,
				DataEndpointEnabled:            &dataEndpointEnabled,
				PrivateEndpointConnectionCount: &privateEndpointConnectionCount,
				WebhookCount:                   &webhookCount,
				EnabledWebhookCount:            &enabledWebhookCount,
				WebhookActionTypes:             []string{},
				BroadWebhookScopeCount:         &broadWebhookScopeCount,
				ReplicationCount:               &replicationCount,
				ReplicationRegions:             []string{},
				QuarantinePolicyStatus:         "disabled",
				RetentionPolicyStatus:          "disabled",
				RetentionPolicyDays:            &retentionPolicyDays,
				TrustPolicyStatus:              "disabled",
				TrustPolicyType:                "notary",
				IdentityType:                   "SystemAssigned",
				WorkloadPrincipalID:            "principal-123",
				WorkloadClientID:               "client-123",
				IdentityIDs:                    []string{},
			},
		},
	}); err != nil {
		t.Fatalf("write acr context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected acr seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsACRPublicNetworkDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-acr-public-network-drift-test",
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
		RunID:      "live-acr-public-network-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "acr",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/acr/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "acr", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"registries":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acr-ops","name":"acr-ops","resource_group":"rg-ops","location":"centralus","state":"Succeeded","login_server":"acr-ops.azurecr.io","sku_name":"Basic","public_network_access":"Disabled","network_rule_bypass_options":"AzureServices","admin_user_enabled":true,"data_endpoint_enabled":false,"private_endpoint_connection_count":0,"webhook_count":0,"enabled_webhook_count":0,"webhook_action_types":[],"broad_webhook_scope_count":0,"replication_count":0,"replication_regions":[],"quarantine_policy_status":"disabled","retention_policy_status":"disabled","retention_policy_days":7,"trust_policy_status":"disabled","trust_policy_type":"notary","workload_identity_type":"SystemAssigned","workload_principal_id":"principal-123","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"acr","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	adminUserEnabled := true
	dataEndpointEnabled := false
	privateEndpointConnectionCount := 0
	webhookCount := 0
	enabledWebhookCount := 0
	broadWebhookScopeCount := 0
	replicationCount := 0
	retentionPolicyDays := 7
	if err := WriteJSON(filepath.Join(payloadDir, "live-acr-context.json"), liveACRContextArtifact{
		Registries: []liveACRTruth{
			{
				ID:                             "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acr-ops",
				Name:                           "acr-ops",
				ResourceGroup:                  "rg-ops",
				Location:                       "centralus",
				State:                          "Succeeded",
				LoginServer:                    "acr-ops.azurecr.io",
				SKUName:                        "Basic",
				PublicNetworkAccess:            "Enabled",
				NetworkRuleBypassOptions:       "AzureServices",
				AdminUserEnabled:               &adminUserEnabled,
				DataEndpointEnabled:            &dataEndpointEnabled,
				PrivateEndpointConnectionCount: &privateEndpointConnectionCount,
				WebhookCount:                   &webhookCount,
				EnabledWebhookCount:            &enabledWebhookCount,
				WebhookActionTypes:             []string{},
				BroadWebhookScopeCount:         &broadWebhookScopeCount,
				ReplicationCount:               &replicationCount,
				ReplicationRegions:             []string{},
				QuarantinePolicyStatus:         "disabled",
				RetentionPolicyStatus:          "disabled",
				RetentionPolicyDays:            &retentionPolicyDays,
				TrustPolicyStatus:              "disabled",
				TrustPolicyType:                "notary",
				IdentityType:                   "SystemAssigned",
				WorkloadPrincipalID:            "principal-123",
				IdentityIDs:                    []string{},
			},
		},
	}); err != nil {
		t.Fatalf("write acr context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected acr public network drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_network_access") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected acr public network drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAPIMSubscriptionCountDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-api-mgmt-subscription-count-drift-test",
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
		RunID:      "live-api-mgmt-subscription-count-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "api-mgmt",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/api-mgmt/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "api-mgmt", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"api_management_services":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ApiManagement/service/apim-ops","name":"apim-ops","resource_group":"rg-ops","location":"Central US","state":"Succeeded","sku_name":"Consumption","sku_capacity":0,"public_network_access":"Enabled","virtual_network_type":"None","public_ip_address_id":null,"public_ip_addresses":[],"private_ip_addresses":[],"gateway_hostnames":["apim-ops.azure-api.net"],"management_hostnames":[],"portal_hostnames":[],"workload_identity_type":"SystemAssigned","workload_principal_id":"principal-123","workload_client_id":null,"workload_identity_ids":[],"gateway_enabled":true,"developer_portal_status":null,"legacy_portal_status":null,"api_count":0,"api_subscription_required_count":0,"subscription_count":0,"active_subscription_count":0,"backend_count":0,"backend_hostnames":[],"named_value_count":0,"named_value_secret_count":0,"named_value_key_vault_count":0,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ApiManagement/service/apim-ops","principal-123"]}],"findings":[],"issues":[],"metadata":{"command":"api-mgmt","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	zero := 0
	one := 1
	gatewayEnabled := true
	if err := WriteJSON(filepath.Join(payloadDir, "live-api-mgmt-context.json"), liveAPIMgmtContextArtifact{
		Services: []liveAPIMgmtTruth{{
			ID:                           "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ApiManagement/service/apim-ops",
			Name:                         "apim-ops",
			ResourceGroup:                "rg-ops",
			Location:                     "Central US",
			State:                        "Succeeded",
			SKUName:                      "Consumption",
			SKUCapacity:                  &zero,
			PublicNetworkAccess:          "Enabled",
			VirtualNetworkType:           "None",
			GatewayHostnames:             []string{"apim-ops.azure-api.net"},
			WorkloadIdentityType:         "SystemAssigned",
			WorkloadPrincipalID:          "principal-123",
			WorkloadIdentityIDs:          []string{},
			GatewayEnabled:               &gatewayEnabled,
			APICount:                     &zero,
			APISubscriptionRequiredCount: &zero,
			SubscriptionCount:            &one,
			ActiveSubscriptionCount:      &one,
			BackendCount:                 &zero,
			BackendHostnames:             []string{},
			NamedValueCount:              &zero,
			NamedValueSecretCount:        &zero,
			NamedValueKeyVaultCount:      &zero,
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ApiManagement/service/apim-ops",
				"principal-123",
			},
		}},
	}); err != nil {
		t.Fatalf("write api-mgmt context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected api-mgmt subscription count drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "subscription_count") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected api-mgmt subscription count drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsApplicationGatewayAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-application-gateway-pass-test",
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
		RunID:      "live-application-gateway-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "application-gateway",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/application-gateway/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "application-gateway", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"application_gateways":[{"id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge","name":"agw-edge","resource_group":"rg-network","location":"centralus","state":"Running","public_frontend_count":1,"public_ip_addresses":["52.238.210.85"],"listener_count":1,"request_routing_rule_count":1,"backend_pool_count":1,"backend_target_count":1,"firewall_policy_id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge","related_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/pip-appgw","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"application-gateway","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-application-gateway-context.json"), liveApplicationGatewayContextArtifact{
		ApplicationGateways: []liveApplicationGatewayTruth{{
			ID:                      "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge",
			Name:                    "agw-edge",
			ResourceGroup:           "rg-network",
			Location:                "centralus",
			State:                   "Running",
			PublicFrontendCount:     1,
			PublicIPAddresses:       []string{"52.238.210.85"},
			ListenerCount:           1,
			RequestRoutingRuleCount: 1,
			BackendPoolCount:        1,
			BackendTargetCount:      1,
			FirewallPolicyID:        "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge",
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/pip-appgw",
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge",
			},
		}},
	}); err != nil {
		t.Fatalf("write application-gateway context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected application-gateway seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsApplicationGatewayReducedViewOmission(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-application-gateway-reduced-pass-test",
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
		RunID:      "live-application-gateway-reduced-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "application-gateway",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/application-gateway/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "application-gateway", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"application_gateways":[],"findings":[],"issues":[],"metadata":{"command":"application-gateway","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-application-gateway-context.json"), liveApplicationGatewayContextArtifact{
		ApplicationGateways: []liveApplicationGatewayTruth{},
	}); err != nil {
		t.Fatalf("write application-gateway context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected reduced application-gateway seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsApplicationGatewayFirewallPolicyDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-application-gateway-firewall-policy-drift-test",
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
		RunID:      "live-application-gateway-firewall-policy-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "application-gateway",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/application-gateway/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "application-gateway", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"application_gateways":[{"id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge","name":"agw-edge","resource_group":"rg-network","location":"centralus","state":"Running","public_frontend_count":1,"public_ip_addresses":["52.238.210.85"],"listener_count":1,"request_routing_rule_count":1,"backend_pool_count":1,"backend_target_count":1,"firewall_policy_id":null,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/pip-appgw"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"application-gateway","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-application-gateway-context.json"), liveApplicationGatewayContextArtifact{
		ApplicationGateways: []liveApplicationGatewayTruth{{
			ID:                      "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge",
			Name:                    "agw-edge",
			ResourceGroup:           "rg-network",
			Location:                "centralus",
			State:                   "Running",
			PublicFrontendCount:     1,
			PublicIPAddresses:       []string{"52.238.210.85"},
			ListenerCount:           1,
			RequestRoutingRuleCount: 1,
			BackendPoolCount:        1,
			BackendTargetCount:      1,
			FirewallPolicyID:        "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/applicationGateways/agw-edge",
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/pip-appgw",
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-edge",
			},
		}},
	}); err != nil {
		t.Fatalf("write application-gateway context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected application-gateway firewall policy drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "firewall_policy_id") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected application-gateway firewall policy drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsVMSAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-vms-pass-test",
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
		RunID:      "live-vms-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "vms",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/vms/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "vms", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"vm_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"location":"centralus","name":"vm-web-01","nic_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"],"power_state":"running","private_ips":["10.42.1.5"],"public_ips":["52.165.253.164"],"resource_group":"rg-workload","vm_type":"vm"}],"findings":[{"id":"vm-public-identity-/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"severity":"medium","title":"Public workload with attached identity"}],"issues":[],"metadata":{"command":"vms","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-vms-context.json"), liveVMSContextArtifact{
		VMAssets: []liveVMTruth{{
			ID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			Name:          "vm-web-01",
			ResourceGroup: "rg-workload",
			Location:      "centralus",
			PowerState:    "running",
			PublicIPs:     []string{"52.165.253.164"},
			PrivateIPs:    []string{"10.42.1.5"},
			IdentityIDs:   []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			NICIDs:        []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"},
			VMType:        "vm",
		}},
	}); err != nil {
		t.Fatalf("write vms context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected vms seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsVMSSameReducedViewWhenAzureStillShowsIt(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-vms-reduced-pass-test",
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
		RunID:      "live-vms-reduced-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "vms",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/vms/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "vms", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"vm_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"location":"centralus","name":"vm-web-01","nic_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"],"power_state":"running","private_ips":["10.42.1.5"],"public_ips":["52.165.253.164"],"resource_group":"rg-workload","vm_type":"vm"}],"findings":[{"id":"vm-public-identity-/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"severity":"medium","title":"Public workload with attached identity"}],"issues":[],"metadata":{"command":"vms","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-vms-context.json"), liveVMSContextArtifact{
		VMAssets: []liveVMTruth{{
			ID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			Name:          "vm-web-01",
			ResourceGroup: "rg-workload",
			Location:      "centralus",
			PowerState:    "running",
			PublicIPs:     []string{"52.165.253.164"},
			PrivateIPs:    []string{"10.42.1.5"},
			IdentityIDs:   []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			NICIDs:        []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"},
			VMType:        "vm",
		}},
	}); err != nil {
		t.Fatalf("write vms context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected reduced-view vms seam to pass cleanly when Azure still shows the VM, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsVMSMissingPublicIdentityFinding(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-vms-finding-drift-test",
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
		RunID:      "live-vms-finding-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "vms",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/vms/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "vms", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"vm_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"location":"centralus","name":"vm-web-01","nic_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"],"power_state":"running","private_ips":["10.42.1.5"],"public_ips":["52.165.253.164"],"resource_group":"rg-workload","vm_type":"vm"}],"findings":[],"issues":[],"metadata":{"command":"vms","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-vms-context.json"), liveVMSContextArtifact{
		VMAssets: []liveVMTruth{{
			ID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			Name:          "vm-web-01",
			ResourceGroup: "rg-workload",
			Location:      "centralus",
			PowerState:    "running",
			PublicIPs:     []string{"52.165.253.164"},
			PrivateIPs:    []string{"10.42.1.5"},
			IdentityIDs:   []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			NICIDs:        []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01"},
			VMType:        "vm",
		}},
	}); err != nil {
		t.Fatalf("write vms context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected vms finding drift, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public-with-identity finding") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected vms finding drift, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsVMSSSubnetDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-vmss-subnet-drift-test",
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
		RunID:      "live-vmss-subnet-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "vmss",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/vmss/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "vmss", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"vmss_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-api","name":"vmss-api","resource_group":"rg-workload","location":"centralus","sku_name":"Standard_B2ts_v2","instance_count":1,"identity_type":"","identity_ids":[],"nic_configuration_count":1,"public_ip_configuration_count":0,"load_balancer_backend_pool_count":0,"inbound_nat_pool_count":0,"application_gateway_backend_pool_count":0,"subnet_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab/subnets/snet-wrong"],"orchestration_mode":"Uniform","upgrade_mode":"Manual","single_placement_group":true,"overprovision":false,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-api"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"vmss","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	instanceCount := 1
	singlePlacementGroup := true
	overprovision := false
	if err := WriteJSON(filepath.Join(payloadDir, "live-vmss-context.json"), liveVMSSContextArtifact{
		VMSSAssets: []liveVMSSTruth{{
			ID:                                 "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-api",
			Name:                               "vmss-api",
			ResourceGroup:                      "rg-workload",
			Location:                           "centralus",
			SKUName:                            "Standard_B2ts_v2",
			InstanceCount:                      &instanceCount,
			IdentityType:                       "",
			IdentityIDs:                        []string{},
			NICConfigurationCount:              1,
			PublicIPConfigurationCount:         0,
			LoadBalancerBackendPoolCount:       0,
			InboundNATPoolCount:                0,
			ApplicationGatewayBackendPoolCount: 0,
			SubnetIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab/subnets/snet-workload",
			},
			OrchestrationMode:    "Uniform",
			UpgradeMode:          "Manual",
			SinglePlacementGroup: &singlePlacementGroup,
			Overprovision:        &overprovision,
		}},
	}); err != nil {
		t.Fatalf("write vmss context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected vmss subnet drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "subnet_ids") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected vmss subnet drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsNICsPublicIPDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-nics-public-ip-drift-test",
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
		RunID:      "live-nics-public-ip-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "nics",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/nics/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "nics", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"nic_assets":[{"attached_asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","attached_asset_name":"vm-web-01","id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01","name":"nic-web-01","network_security_group_id":null,"private_ips":["10.42.1.5"],"public_ip_ids":[],"subnet_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab/subnets/snet-workload"],"vnet_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab"]}],"findings":[],"issues":[],"metadata":{"command":"nics","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-nics-context.json"), liveNICContextArtifact{
		NICAssets: []liveNICTruth{{
			ID:                "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01",
			Name:              "nic-web-01",
			AttachedAssetID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			AttachedAssetName: "vm-web-01",
			PrivateIPs:        []string{"10.42.1.5"},
			PublicIPIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/publicIPAddresses/pip-vm-web-01",
			},
			SubnetIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab/subnets/snet-workload",
			},
			VnetIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hoazurelab",
			},
		}},
	}); err != nil {
		t.Fatalf("write nics context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected nics public IP drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_ip_ids") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nics public IP drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsDatabasesUserDatabaseNamesDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-databases-user-db-drift-test",
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
		RunID:      "live-databases-user-db-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "databases",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/databases/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "databases", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"database_servers":[{"database_count":1,"engine":"AzureSql","fully_qualified_domain_name":"sql-hoazurel-a43cfa.database.windows.net","id":"/subscriptions/sub-123/resourceGroups/rg-hoazurelab-data/providers/Microsoft.Sql/servers/sql-hoazurel-a43cfa","location":"centralus","minimal_tls_version":"1.2","name":"sql-hoazurel-a43cfa","public_network_access":"Enabled","related_ids":["/subscriptions/sub-123/resourceGroups/rg-hoazurelab-data/providers/Microsoft.Sql/servers/sql-hoazurel-a43cfa"],"resource_group":"rg-hoazurelab-data","server_version":"12.0","state":"Ready","user_database_names":["wrongdb"],"workload_identity_ids":[]}],"findings":[],"issues":[],"metadata":{"command":"databases","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	count := 1
	if err := WriteJSON(filepath.Join(payloadDir, "live-databases-context.json"), liveDatabasesContextArtifact{
		DatabaseServers: []liveDatabaseServerTruth{{
			ID:                       "/subscriptions/sub-123/resourceGroups/rg-hoazurelab-data/providers/Microsoft.Sql/servers/sql-hoazurel-a43cfa",
			Name:                     "sql-hoazurel-a43cfa",
			ResourceGroup:            "rg-hoazurelab-data",
			Location:                 "centralus",
			Engine:                   "AzureSql",
			FullyQualifiedDomainName: "sql-hoazurel-a43cfa.database.windows.net",
			PublicNetworkAccess:      "Enabled",
			MinimalTLSVersion:        "1.2",
			ServerVersion:            "12.0",
			State:                    "Ready",
			DatabaseCount:            &count,
			UserDatabaseNames:        []string{"appdb"},
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-hoazurelab-data/providers/Microsoft.Sql/servers/sql-hoazurel-a43cfa",
			},
		}},
	}); err != nil {
		t.Fatalf("write databases context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected databases user database names drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "user_database_names") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected databases user database names drift finding, got %#v", summary.Findings)
	}
}

func TestRunValidationExecutesFullGoFlow(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "uniform")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}
	manifest.Viewpoints["dev"] = ViewpointDefinition{Required: false, Description: "Developer viewpoint"}
	manifest.Viewpoints["lower-privilege"] = ViewpointDefinition{Required: false, Description: "Lower-privilege viewpoint"}
	whoami := manifest.Surfaces.Commands["whoami"]
	whoami.Status = "covered"
	whoami.ReasonCode = ""
	whoami.ReasonDetail = ""
	whoami.Viewpoints["admin"] = ViewpointStatus{Status: "covered"}
	manifest.Surfaces.Commands["whoami"] = whoami

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := WriteJSON(manifestPath, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	setupFakeAzureCLI(t, fakeAzureContext{
		SubscriptionID: "sub-123",
		TenantID:       "tenant-123",
		PrincipalID:    "principal-123",
		PrincipalName:  "ua-app",
		PrincipalType:  "ManagedIdentity",
	})
	toolPath := filepath.Join(t.TempDir(), "fake-azurefox")
	if err := os.WriteFile(toolPath, []byte(fakeWhoAmIScript(`{"tenant_id":"tenant-123","subscription":{"id":"sub-123","display_name":"lab-sub","state":"Enabled"},"principal":{"id":"principal-123","display_name":"ua-app","principal_type":"ManagedIdentity","tenant_id":"tenant-123"},"effective_scopes":[],"issues":[],"metadata":{"command":"whoami","generated_at":"2026-04-19T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`)), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	outputDir := t.TempDir()
	var progress bytes.Buffer
	exitCode, err := RunValidation(AzureRunConfig{
		ManifestPath:   manifestPath,
		OutputDir:      outputDir,
		HOAzureDir:     hoAzureDir,
		ToolBin:        toolPath,
		RunID:          "full-go-test",
		Viewpoint:      "all",
		ProgressWriter: &progress,
	})
	if err != nil {
		t.Fatalf("run validation: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected successful full validation exit, got %d", exitCode)
	}

	runResults := RunResult{}
	if err := LoadJSON(filepath.Join(outputDir, "run-result.json"), &runResults); err != nil {
		t.Fatalf("load run results: %v", err)
	}
	if runResults.FinalOutcome != "pass" {
		t.Fatalf("expected pass final outcome, got %#v", runResults.FinalOutcome)
	}

	summary := ValidationSummary{}
	if err := LoadJSON(filepath.Join(outputDir, "artifacts", "completion-summary.json"), &summary); err != nil {
		t.Fatalf("load completion summary: %v", err)
	}
	if !summary.ReleaseReady {
		t.Fatalf("expected release-ready completion summary, got %#v", summary)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "live-validation-summary.json")); err != nil {
		t.Fatalf("expected live validation summary artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "completion-summary.txt")); err != nil {
		t.Fatalf("expected completion summary text artifact: %v", err)
	}
	progressText := progress.String()
	if !strings.Contains(progressText, "Starting Azure validation flow...") {
		t.Fatalf("expected validation start progress, got %q", progressText)
	}
	if !strings.Contains(progressText, "Running live payload checks...") {
		t.Fatalf("expected live payload progress, got %q", progressText)
	}
	if !strings.Contains(progressText, "Azure validation succeeded.") {
		t.Fatalf("expected success progress, got %q", progressText)
	}
}

func TestResolveRunContextLoadsViewpointsFromInfraOutputs(t *testing.T) {
	infraDir := t.TempDir()
	fakeTofuPath := filepath.Join(t.TempDir(), "fake-tofu")
	outputJSON := `{"validation_viewpoints":{"value":{"dev":{"client_id":"dev-client","client_secret":"dev-secret","tenant_id":"tenant-123","subscription_id":"sub-123"},"lower_privilege":{"client_id":"low-client","client_secret":"low-secret","tenant_id":"tenant-123","subscription_id":"sub-123"}}},"tenant_id":{"value":"tenant-123"},"subscription_id":{"value":"sub-123"}}`
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"output\" ] && [ \"$2\" = \"-json\" ]; then",
		fmt.Sprintf("  printf '%%s' %s", shellQuote(outputJSON)),
		"  exit 0",
		"fi",
		"echo unexpected invocation >&2",
		"exit 1",
	}, "\n")
	if err := os.WriteFile(fakeTofuPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tofu: %v", err)
	}

	var progress bytes.Buffer
	credentials, tenant, subscription, err := resolveRunContext(AzureRunConfig{
		InfraDir:       infraDir,
		TofuBinary:     fakeTofuPath,
		ProgressWriter: &progress,
	}, []string{"admin", "dev", "lower-privilege"})
	if err != nil {
		t.Fatalf("resolve run context: %v", err)
	}

	if tenant != "tenant-123" {
		t.Fatalf("expected tenant from infra outputs, got %q", tenant)
	}
	if subscription != "sub-123" {
		t.Fatalf("expected subscription from infra outputs, got %q", subscription)
	}
	if credentials["dev"]["client_id"] != "dev-client" {
		t.Fatalf("expected dev credentials from infra outputs, got %#v", credentials["dev"])
	}
	if credentials["lower_privilege"]["client_id"] != "low-client" {
		t.Fatalf("expected lower-privilege credentials from infra outputs, got %#v", credentials["lower_privilege"])
	}
	if !strings.Contains(progress.String(), "Loaded reduced-viewpoint credentials from lab outputs.") {
		t.Fatalf("expected lab-output progress message, got %q", progress.String())
	}
}

func TestResolveRunContextAllowsAdminOnlyWithoutInfraOutputs(t *testing.T) {
	credentials, tenant, subscription, err := resolveRunContext(AzureRunConfig{
		Tenant:       "tenant-123",
		Subscription: "sub-123",
	}, []string{"admin"})
	if err != nil {
		t.Fatalf("resolve run context: %v", err)
	}
	if len(credentials) != 0 {
		t.Fatalf("expected no reduced-viewpoint credentials for admin-only run, got %#v", credentials)
	}
	if tenant != "tenant-123" {
		t.Fatalf("expected tenant to pass through, got %q", tenant)
	}
	if subscription != "sub-123" {
		t.Fatalf("expected subscription to pass through, got %q", subscription)
	}
}

func TestResolveRunContextFailsClearlyWhenReducedViewpointsHaveNoCredentials(t *testing.T) {
	_, _, _, err := resolveRunContext(AzureRunConfig{}, []string{"admin", "dev"})
	if err == nil {
		t.Fatalf("expected reduced-viewpoint credential error")
	}
	if !strings.Contains(err.Error(), "reduced viewpoints need either --viewpoint-credentials or --infra-dir with lab outputs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupViewpointSessionUsesSystemTempDirForAzureConfigDir(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "az.log")
	fakeAzPath := filepath.Join(binDir, "az")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$AZURE_CONFIG_DIR|$@\" >> %s", shellQuote(logPath)),
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeAzPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake az: %v", err)
	}

	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+originalPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	defer func() {
		_ = os.Setenv("PATH", originalPath)
	}()

	var progress bytes.Buffer
	configDir, env, tenant, subscription, err := setupViewpointSession("dev", map[string]string{
		"client_id":       "dev-client",
		"client_secret":   "dev-secret",
		"tenant_id":       "tenant-123",
		"subscription_id": "sub-123",
	}, "", "", t.TempDir(), &progress)
	if err != nil {
		t.Fatalf("setup viewpoint session: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(configDir)
	}()

	tempRoot := azureViewpointConfigRoot()
	expectedPrefix := filepath.Join(tempRoot, "ho-azure-dev-")
	if !strings.HasPrefix(configDir, expectedPrefix) {
		t.Fatalf("expected config dir under %s, got %q", tempRoot, configDir)
	}
	if tenant != "tenant-123" {
		t.Fatalf("expected tenant passthrough, got %q", tenant)
	}
	if subscription != "sub-123" {
		t.Fatalf("expected subscription passthrough, got %q", subscription)
	}
	if !slices.Contains(env, "AZURE_CONFIG_DIR="+configDir) {
		t.Fatalf("expected env to include AZURE_CONFIG_DIR, got %#v", env)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read az log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, configDir+"|login --service-principal --username dev-client --password dev-secret --tenant tenant-123 --allow-no-subscriptions") {
		t.Fatalf("expected az login with system temp config dir, got %q", logText)
	}
	if !strings.Contains(logText, configDir+"|account set --subscription sub-123") {
		t.Fatalf("expected az account set with tmp config dir, got %q", logText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "[start] az login (dev viewpoint)") {
		t.Fatalf("expected az login progress start, got %q", progressText)
	}
	if !strings.Contains(progressText, "[done] az login (dev viewpoint) -> status=pass") {
		t.Fatalf("expected az login progress completion, got %q", progressText)
	}
	if !strings.Contains(progressText, "[start] az account set (dev viewpoint)") {
		t.Fatalf("expected az account set progress start, got %q", progressText)
	}
	if !strings.Contains(progressText, "[done] az account set (dev viewpoint) -> status=pass") {
		t.Fatalf("expected az account set progress completion, got %q", progressText)
	}
}

func TestSetupAdminAmbientSessionCopiesAzureConfigIntoTempDir(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "az.log")
	sourceConfigDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceConfigDir, "azureProfile.json"), []byte(`{"subscriptions":[]}`), 0o600); err != nil {
		t.Fatalf("write source Azure profile: %v", err)
	}

	fakeAzPath := filepath.Join(binDir, "az")
	script := strings.Join([]string{
		"#!/bin/sh",
		fmt.Sprintf("echo \"$AZURE_CONFIG_DIR|$@\" >> %s", shellQuote(logPath)),
		"if [ \"$1\" = \"account\" ] && [ \"$2\" = \"show\" ]; then",
		"  printf '%s\\n' '{\"id\":\"sub-123\",\"tenantId\":\"tenant-123\"}'",
		"  exit 0",
		"fi",
		"exit 0",
	}, "\n")
	if err := os.WriteFile(fakeAzPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake az: %v", err)
	}

	originalPath := os.Getenv("PATH")
	originalAzureConfigDir, hadAzureConfigDir := os.LookupEnv("AZURE_CONFIG_DIR")
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+originalPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	if err := os.Setenv("AZURE_CONFIG_DIR", sourceConfigDir); err != nil {
		t.Fatalf("set AZURE_CONFIG_DIR: %v", err)
	}
	defer func() {
		_ = os.Setenv("PATH", originalPath)
		if hadAzureConfigDir {
			_ = os.Setenv("AZURE_CONFIG_DIR", originalAzureConfigDir)
			return
		}
		_ = os.Unsetenv("AZURE_CONFIG_DIR")
	}()

	var progress bytes.Buffer
	configDir, env, tenant, subscription, err := setupAdminAmbientSession("", "", t.TempDir(), &progress)
	if err != nil {
		t.Fatalf("setup admin ambient session: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(configDir)
	}()

	tempRoot := azureViewpointConfigRoot()
	expectedPrefix := filepath.Join(tempRoot, "ho-azure-admin-")
	if !strings.HasPrefix(configDir, expectedPrefix) {
		t.Fatalf("expected config dir under %s, got %q", tempRoot, configDir)
	}
	if tenant != "tenant-123" {
		t.Fatalf("expected tenant passthrough, got %q", tenant)
	}
	if subscription != "sub-123" {
		t.Fatalf("expected subscription passthrough, got %q", subscription)
	}
	if !slices.Contains(env, "AZURE_CONFIG_DIR="+configDir) {
		t.Fatalf("expected env to include AZURE_CONFIG_DIR, got %#v", env)
	}
	if configDir == sourceConfigDir {
		t.Fatalf("expected temp config dir distinct from source config dir")
	}

	copiedProfilePath := filepath.Join(configDir, "azureProfile.json")
	copiedProfile, err := os.ReadFile(copiedProfilePath)
	if err != nil {
		t.Fatalf("read copied Azure profile: %v", err)
	}
	if string(copiedProfile) != `{"subscriptions":[]}` {
		t.Fatalf("expected copied Azure profile, got %q", string(copiedProfile))
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read az log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, configDir+"|account show --output json") {
		t.Fatalf("expected az account show with temp admin config dir, got %q", logText)
	}
	if !strings.Contains(logText, configDir+"|account set --subscription sub-123") {
		t.Fatalf("expected az account set with temp admin config dir, got %q", logText)
	}

	progressText := progress.String()
	if !strings.Contains(progressText, "[start] az account show (admin viewpoint)") {
		t.Fatalf("expected az account show progress start, got %q", progressText)
	}
	if !strings.Contains(progressText, "[done] az account set (admin viewpoint) -> status=pass") {
		t.Fatalf("expected az account set progress completion, got %q", progressText)
	}
}

func TestSetupAdminAmbientSessionFailsClearlyWithoutAmbientAzureConfig(t *testing.T) {
	originalAzureConfigDir, hadAzureConfigDir := os.LookupEnv("AZURE_CONFIG_DIR")
	if err := os.Setenv("AZURE_CONFIG_DIR", filepath.Join(t.TempDir(), "missing-azure-config")); err != nil {
		t.Fatalf("set AZURE_CONFIG_DIR: %v", err)
	}
	defer func() {
		if hadAzureConfigDir {
			_ = os.Setenv("AZURE_CONFIG_DIR", originalAzureConfigDir)
			return
		}
		_ = os.Unsetenv("AZURE_CONFIG_DIR")
	}()

	_, _, _, _, err := setupAdminAmbientSession("", "", t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected missing ambient admin Azure config error")
	}
	if !strings.Contains(err.Error(), "admin viewpoint needs an active Azure CLI config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteTaskTimesOutAndRecordsFailure(t *testing.T) {
	if os.Getenv("GO_WANT_INACTIVITY_TIMEOUT_HELPER") == "1" {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}

	outputDir := t.TempDir()
	entry, status, notes := executeTask(
		SurfaceTask{
			SurfaceKind:  "commands",
			SurfaceName:  "whoami",
			Viewpoint:    "admin",
			GroupCommand: "whoami",
		},
		[]string{os.Args[0], "-test.run=TestExecuteTaskTimesOutAndRecordsFailure", "--"},
		t.TempDir(),
		outputDir,
		"tenant-123",
		"sub-123",
		"",
		append(os.Environ(), "GO_WANT_INACTIVITY_TIMEOUT_HELPER=1"),
		0,
		50*time.Millisecond,
		nil,
	)

	if status != "fail" {
		t.Fatalf("expected timeout status fail, got %q", status)
	}
	if !strings.Contains(notes, "went quiet") {
		t.Fatalf("expected inactivity-timeout notes, got %q", notes)
	}
	if !strings.Contains(notes, "longer inactivity timeout or disable it") {
		t.Fatalf("expected rerun guidance in timeout notes, got %q", notes)
	}
	if entry.ExitCode != -1 {
		t.Fatalf("expected timeout exit code -1, got %d", entry.ExitCode)
	}
	if entry.Status != "fail" {
		t.Fatalf("expected command log fail status, got %q", entry.Status)
	}
	if entry.StderrPath == "" {
		t.Fatalf("expected timeout stderr artifact path")
	}

	stderrPath := filepath.Join(outputDir, filepath.FromSlash(entry.StderrPath))
	stderrData, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatalf("read stderr artifact: %v", err)
	}
	if !strings.Contains(string(stderrData), "no output or artifact updates") {
		t.Fatalf("expected timeout text in stderr artifact, got %q", string(stderrData))
	}
}

func TestExecuteTaskAllowsArtifactActivityToKeepRunAlive(t *testing.T) {
	if os.Getenv("GO_WANT_ARTIFACT_ACTIVITY_HELPER") == "1" {
		outdir := os.Getenv("GO_ARTIFACT_OUTDIR")
		loopPath := filepath.Join(outdir, "loop.txt")
		for i := 0; i < 4; i++ {
			if err := os.WriteFile(loopPath, []byte(fmt.Sprintf("tick-%d\n", i)), 0o644); err != nil {
				os.Exit(1)
			}
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Println(`{"tenant_id":"tenant-123","subscription":{},"principal":{},"effective_scopes":[],"issues":[]}`)
		os.Exit(0)
	}

	outputDir := t.TempDir()
	baseEnv := append([]string{}, os.Environ()...)
	baseEnv = append(baseEnv, "GO_WANT_ARTIFACT_ACTIVITY_HELPER=1")
	entry, status, notes := executeTask(
		SurfaceTask{
			SurfaceKind:  "commands",
			SurfaceName:  "whoami",
			Viewpoint:    "admin",
			GroupCommand: "whoami",
		},
		[]string{os.Args[0], "-test.run=TestExecuteTaskAllowsArtifactActivityToKeepRunAlive", "--"},
		t.TempDir(),
		outputDir,
		"tenant-123",
		"sub-123",
		"",
		append(baseEnv, "GO_ARTIFACT_OUTDIR="+filepath.Join(outputDir, "artifacts", "payloads", "commands", "whoami", "admin")),
		0,
		80*time.Millisecond,
		nil,
	)

	if status != "pass" {
		t.Fatalf("expected artifact activity to keep run alive, got status=%q notes=%q entry=%#v", status, notes, entry)
	}
	if entry.Status != "pass" {
		t.Fatalf("expected pass command log entry, got %#v", entry)
	}
	if entry.PayloadPath == "" {
		t.Fatalf("expected payload artifact path for successful run")
	}
	if entry.TablePath == "" {
		t.Fatalf("expected table artifact path for successful run")
	}
}

func TestExecuteTaskCapturesJSONAndTableArtifacts(t *testing.T) {
	if os.Getenv("GO_WANT_EXECUTE_TASK_ARTIFACT_HELPER") == "1" {
		outputFormat := ""
		for i, arg := range os.Args {
			if arg == "--output" && i+1 < len(os.Args) {
				outputFormat = os.Args[i+1]
				break
			}
		}
		switch outputFormat {
		case "json":
			fmt.Println(`{"tenant_id":"tenant-123","subscription":{},"principal":{},"effective_scopes":[],"issues":[]}`)
			os.Exit(0)
		case "table":
			fmt.Println("TENANT")
			fmt.Println("tenant-123")
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unexpected output format %q", outputFormat)
			os.Exit(2)
		}
	}

	outputDir := t.TempDir()
	entry, status, notes := executeTask(
		SurfaceTask{
			SurfaceKind:  "commands",
			SurfaceName:  "whoami",
			Viewpoint:    "admin",
			GroupCommand: "whoami",
		},
		[]string{os.Args[0], "-test.run=TestExecuteTaskCapturesJSONAndTableArtifacts", "--"},
		t.TempDir(),
		outputDir,
		"tenant-123",
		"sub-123",
		"",
		append(os.Environ(), "GO_WANT_EXECUTE_TASK_ARTIFACT_HELPER=1"),
		0,
		0,
		nil,
	)

	if status != "pass" {
		t.Fatalf("expected pass status, got status=%q notes=%q entry=%#v", status, notes, entry)
	}
	if entry.PayloadPath == "" {
		t.Fatalf("expected payload artifact path")
	}
	if entry.TablePath == "" {
		t.Fatalf("expected table artifact path")
	}
	if _, err := os.Stat(filepath.Join(outputDir, filepath.FromSlash(entry.PayloadPath))); err != nil {
		t.Fatalf("expected payload artifact on disk: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, filepath.FromSlash(entry.TablePath))); err != nil {
		t.Fatalf("expected table artifact on disk: %v", err)
	}
}

func TestExecuteTaskFailsWhenTableRerunFails(t *testing.T) {
	if os.Getenv("GO_WANT_EXECUTE_TASK_TABLE_FAILURE_HELPER") == "1" {
		outputFormat := ""
		for i, arg := range os.Args {
			if arg == "--output" && i+1 < len(os.Args) {
				outputFormat = os.Args[i+1]
				break
			}
		}
		switch outputFormat {
		case "json":
			fmt.Println(`{"tenant_id":"tenant-123","subscription":{},"principal":{},"effective_scopes":[],"issues":[]}`)
			os.Exit(0)
		case "table":
			fmt.Fprintln(os.Stderr, "table render failed")
			os.Exit(7)
		default:
			fmt.Fprintf(os.Stderr, "unexpected output format %q", outputFormat)
			os.Exit(2)
		}
	}

	outputDir := t.TempDir()
	entry, status, notes := executeTask(
		SurfaceTask{
			SurfaceKind:  "commands",
			SurfaceName:  "whoami",
			Viewpoint:    "admin",
			GroupCommand: "whoami",
		},
		[]string{os.Args[0], "-test.run=TestExecuteTaskFailsWhenTableRerunFails", "--"},
		t.TempDir(),
		outputDir,
		"tenant-123",
		"sub-123",
		"",
		append(os.Environ(), "GO_WANT_EXECUTE_TASK_TABLE_FAILURE_HELPER=1"),
		0,
		0,
		nil,
	)

	if status != "fail" {
		t.Fatalf("expected fail status when table rerun fails, got status=%q notes=%q entry=%#v", status, notes, entry)
	}
	if !strings.Contains(notes, "table rerun failed with exit code 7") {
		t.Fatalf("expected table rerun failure note, got %q", notes)
	}
	if entry.PayloadPath == "" {
		t.Fatalf("expected payload artifact path even when table rerun fails")
	}
	if entry.TablePath != "" {
		t.Fatalf("expected no table artifact path on table rerun failure, got %q", entry.TablePath)
	}
	if entry.ExitCode != 7 {
		t.Fatalf("expected table exit code 7 to be surfaced, got %d entry=%#v notes=%q", entry.ExitCode, entry, notes)
	}
}

func TestRunAzureValidationFlagsSlowCommandsAsFindings(t *testing.T) {
	setupFakeAzureCLI(t, fakeAzureContext{
		SubscriptionID: "sub-123",
		TenantID:       "tenant-123",
		PrincipalID:    "principal-123",
		PrincipalName:  "ua-app",
		PrincipalType:  "ManagedIdentity",
	})
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "uniform")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}
	manifest.Viewpoints["dev"] = ViewpointDefinition{Required: false, Description: "Developer viewpoint"}
	manifest.Viewpoints["lower-privilege"] = ViewpointDefinition{Required: false, Description: "Lower-privilege viewpoint"}
	whoami := manifest.Surfaces.Commands["whoami"]
	whoami.Status = "covered"
	whoami.ReasonCode = ""
	whoami.ReasonDetail = ""
	whoami.Viewpoints["admin"] = ViewpointStatus{Status: "covered"}
	manifest.Surfaces.Commands["whoami"] = whoami

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := WriteJSON(manifestPath, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	fakeToolPath := filepath.Join(t.TempDir(), "slow-tool")
	script := strings.Join([]string{
		"#!/bin/sh",
		"sleep 0.2",
		"cat <<'EOF'",
		`{"tenant_id":"tenant-123","subscription":{},"principal":{},"effective_scopes":[],"issues":[]}`,
		"EOF",
	}, "\n")
	if err := os.WriteFile(fakeToolPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	outputDir := t.TempDir()
	exitCode, err := RunAzureValidation(AzureRunConfig{
		ManifestPath:             manifestPath,
		OutputDir:                outputDir,
		HOAzureDir:               hoAzureDir,
		ToolBin:                  fakeToolPath,
		RunID:                    "slow-command-run",
		Viewpoint:                "admin",
		CommandTimeout:           0,
		CommandInactivityTimeout: 0,
		CommandSlowThreshold:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("run azure validation: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected slow-command run to return 1 for findings, got %d", exitCode)
	}

	var runResult RunResult
	if err := LoadJSON(filepath.Join(outputDir, "run-result.json"), &runResult); err != nil {
		t.Fatalf("load run result: %v", err)
	}
	if runResult.FinalOutcome != "fix-now" {
		t.Fatalf("expected fix-now outcome for slow command, got %#v", runResult.FinalOutcome)
	}
	if len(runResult.Findings) == 0 {
		t.Fatalf("expected slow-command finding, got none")
	}
	if !strings.Contains(runResult.Findings[0].Summary, "exceeding the slow-command threshold") {
		t.Fatalf("unexpected slow-command finding: %#v", runResult.Findings[0])
	}
	if !strings.Contains(runResult.SurfaceResults.Commands["whoami"]["admin"].Notes, "exceeded the slow-command threshold") {
		t.Fatalf("expected slow-command note on viewpoint result, got %#v", runResult.SurfaceResults.Commands["whoami"]["admin"])
	}
}

func fakeToolScript(fields []string) string {
	lines := []string{"#!/bin/sh", "cat <<'EOF'", "{", ""}
	for idx, field := range fields {
		suffix := ","
		if idx == len(fields)-1 {
			suffix = ""
		}
		lines = append(lines, fmt.Sprintf("  %q: null%s", field, suffix))
	}
	lines = append(lines, "}", "EOF")
	return strings.Join(lines, "\n")
}

type fakeAzureContext struct {
	SubscriptionID string
	TenantID       string
	PrincipalID    string
	PrincipalName  string
	PrincipalType  string
}

func setupFakeAzureCLI(t *testing.T, context fakeAzureContext) {
	t.Helper()
	binDir := t.TempDir()
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "azureProfile.json"), []byte(`{"subscriptions":[]}`), 0o600); err != nil {
		t.Fatalf("write fake Azure profile: %v", err)
	}
	fakeAzPath := filepath.Join(binDir, "az")
	accountShow := fmt.Sprintf(`{"id":%q,"tenantId":%q,"user":{"name":%q,"type":"servicePrincipal"}}`, context.SubscriptionID, context.TenantID, context.PrincipalName)
	tokenPayload := fakeAzureAccessToken(context)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"account\" ] && [ \"$2\" = \"show\" ]; then",
		fmt.Sprintf("  printf '%%s' %s", shellQuote(accountShow)),
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"account\" ] && [ \"$2\" = \"get-access-token\" ]; then",
		fmt.Sprintf("  printf '%%s' %s", shellQuote(fmt.Sprintf(`{"accessToken":%q}`, tokenPayload))),
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"account\" ] && [ \"$2\" = \"set\" ]; then",
		"  exit 0",
		"fi",
		"echo unexpected az invocation >&2",
		"exit 1",
	}, "\n")
	if err := os.WriteFile(fakeAzPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake az: %v", err)
	}

	originalPath := os.Getenv("PATH")
	originalAzureConfigDir, hadAzureConfigDir := os.LookupEnv("AZURE_CONFIG_DIR")
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+originalPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	if err := os.Setenv("AZURE_CONFIG_DIR", configDir); err != nil {
		t.Fatalf("set AZURE_CONFIG_DIR: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", originalPath)
		if hadAzureConfigDir {
			_ = os.Setenv("AZURE_CONFIG_DIR", originalAzureConfigDir)
			return
		}
		_ = os.Unsetenv("AZURE_CONFIG_DIR")
	})
}

func fakeAzureAccessToken(context fakeAzureContext) string {
	claims := map[string]any{
		"tid":  context.TenantID,
		"oid":  context.PrincipalID,
		"name": context.PrincipalName,
	}
	if context.PrincipalType == "ManagedIdentity" {
		claims["xms_mirid"] = "/subscriptions/" + context.SubscriptionID + "/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + context.PrincipalName
	} else {
		claims["idtyp"] = "app"
		claims["appid"] = context.PrincipalName
	}
	body, _ := json.Marshal(claims)
	return "header." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func fakeWhoAmIScript(payload string) string {
	return strings.Join([]string{
		"#!/bin/sh",
		"cat <<'EOF'",
		payload,
		"EOF",
	}, "\n")
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}

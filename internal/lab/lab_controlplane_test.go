package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunAcceptsLogicAppsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-logic-apps-pass-test",
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
		RunID:      "live-logic-apps-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "logic-apps",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/logic-apps/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "logic-apps", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workflows":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound","logic_app":"la-inbound","classification":"persistence-capable","resource_group":"rg-workload","location":"centralus","platform":"Consumption","workflow_kind":"Stateful","state":"Enabled","identity_type":"SystemAssigned","principal_id":"principal-123","client_id":"client-123","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound/identities/system"],"trigger_types":["request"],"externally_callable_request_trigger":true,"downstream_action_kinds":["external-http"],"summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound/identities/system"]}],"findings":[],"issues":[],"metadata":{"command":"logic-apps","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-logic-apps-context.json"), liveLogicAppsContextArtifact{
		Workflows: []liveLogicAppTruth{{
			ID:                               "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound",
			Name:                             "la-inbound",
			ResourceGroup:                    "rg-workload",
			Location:                         "centralus",
			State:                            "Enabled",
			WorkflowKind:                     "Stateful",
			IdentityType:                     "SystemAssigned",
			PrincipalID:                      "principal-123",
			ClientID:                         "client-123",
			IdentityIDs:                      []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound/identities/system"},
			TriggerTypes:                     []string{"request"},
			ExternallyCallableRequestTrigger: true,
			DownstreamActionKinds:            []string{"external-http"},
			Classification:                   "persistence-capable",
		}},
	}); err != nil {
		t.Fatalf("write logic apps context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected logic-apps seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsLogicAppsIdentityDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-logic-apps-identity-drift-test",
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
		RunID:      "live-logic-apps-identity-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "logic-apps",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/logic-apps/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "logic-apps", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workflows":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound","logic_app":"la-inbound","classification":"persistence-capable","resource_group":"rg-workload","location":"centralus","state":"Enabled","identity_type":"SystemAssigned","principal_id":"principal-123","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound/identities/system","principalId","tenantId","type"],"trigger_types":["request"],"externally_callable_request_trigger":true,"downstream_action_kinds":["external-http"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"logic-apps","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-logic-apps-context.json"), liveLogicAppsContextArtifact{
		Workflows: []liveLogicAppTruth{{
			ID:                               "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound",
			Name:                             "la-inbound",
			ResourceGroup:                    "rg-workload",
			Location:                         "centralus",
			State:                            "Enabled",
			IdentityType:                     "SystemAssigned",
			PrincipalID:                      "principal-123",
			IdentityIDs:                      []string{"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-inbound/identities/system"},
			TriggerTypes:                     []string{"request"},
			ExternallyCallableRequestTrigger: true,
			DownstreamActionKinds:            []string{"external-http"},
			Classification:                   "persistence-capable",
		}},
	}); err != nil {
		t.Fatalf("write logic apps context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected logic-apps identity drift finding, got %#v", summary.Findings)
	}
	if !strings.Contains(summary.Findings[0].Summary, "identity_ids") {
		t.Fatalf("expected identity_ids drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsAutomationAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-automation-pass-test",
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
		RunID:      "live-automation-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "automation",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/automation/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "automation", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"automation_accounts":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops","name":"aa-ops","resource_group":"rg-ops","location":"centralus","state":"Ok","sku_name":"Basic","identity_type":"SystemAssigned","principal_id":"principal-123","client_id":"","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system"],"runbook_count":0,"published_runbook_count":0,"published_runbook_names":[],"schedule_count":0,"job_schedule_count":0,"webhook_count":0,"hybrid_worker_group_count":0,"credential_count":0,"certificate_count":0,"connection_count":0,"variable_count":0,"encrypted_variable_count":0,"start_modes":[],"primary_start_mode":null,"primary_runbook_name":null,"schedule_runbook_names":[],"webhook_runbook_names":[],"hybrid_worker_group_ids":[],"trigger_join_ids":[],"identity_join_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system","principal-123"],"secret_support_types":[],"secret_dependency_ids":[],"consequence_types":["run-recurring-execution"],"missing_execution_path":true,"missing_target_mapping":true,"summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system"]}],"findings":[],"issues":[],"metadata":{"command":"automation","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	zero := 0
	if err := WriteJSON(filepath.Join(payloadDir, "live-automation-context.json"), liveAutomationContextArtifact{
		AutomationAccounts: []liveAutomationTruth{{
			ID:                     "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops",
			Name:                   "aa-ops",
			ResourceGroup:          "rg-ops",
			Location:               "centralus",
			State:                  "Ok",
			SKUName:                "Basic",
			IdentityType:           "SystemAssigned",
			PrincipalID:            "principal-123",
			IdentityIDs:            []string{"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system"},
			RunbookCount:           &zero,
			PublishedRunbookCount:  &zero,
			ScheduleCount:          &zero,
			JobScheduleCount:       &zero,
			WebhookCount:           &zero,
			HybridWorkerGroupCount: &zero,
			CredentialCount:        &zero,
			CertificateCount:       &zero,
			ConnectionCount:        &zero,
			VariableCount:          &zero,
			EncryptedVariableCount: &zero,
		}},
	}); err != nil {
		t.Fatalf("write automation context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected automation seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAutomationIdentityDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-automation-identity-drift-test",
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
		RunID:      "live-automation-identity-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "automation",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/automation/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "automation", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"automation_accounts":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops","name":"aa-ops","resource_group":"rg-ops","location":"centralus","state":"Ok","sku_name":null,"identity_type":"SystemAssigned","principal_id":"principal-123","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system","principalId","tenantId","type"],"runbook_count":0,"published_runbook_count":0,"schedule_count":0,"job_schedule_count":0,"webhook_count":0,"hybrid_worker_group_count":0,"credential_count":0,"certificate_count":0,"connection_count":0,"variable_count":0,"encrypted_variable_count":0,"identity_join_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system","principalId","tenantId","type","principal-123"],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system","principalId","tenantId","type"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"automation","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	zero := 0
	if err := WriteJSON(filepath.Join(payloadDir, "live-automation-context.json"), liveAutomationContextArtifact{
		AutomationAccounts: []liveAutomationTruth{{
			ID:                     "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops",
			Name:                   "aa-ops",
			ResourceGroup:          "rg-ops",
			Location:               "centralus",
			State:                  "Ok",
			SKUName:                "Basic",
			IdentityType:           "SystemAssigned",
			PrincipalID:            "principal-123",
			IdentityIDs:            []string{"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops/identities/system"},
			RunbookCount:           &zero,
			PublishedRunbookCount:  &zero,
			ScheduleCount:          &zero,
			JobScheduleCount:       &zero,
			WebhookCount:           &zero,
			HybridWorkerGroupCount: &zero,
			CredentialCount:        &zero,
			CertificateCount:       &zero,
			ConnectionCount:        &zero,
			VariableCount:          &zero,
			EncryptedVariableCount: &zero,
		}},
	}); err != nil {
		t.Fatalf("write automation context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected automation drift finding, got %#v", summary.Findings)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "identity_ids") || strings.Contains(finding.Summary, "sku_name") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected automation identity or sku drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsEventGridAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-event-grid-pass-test",
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
		RunID:      "live-event-grid-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "event-grid",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/event-grid/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "event-grid", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"routes":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/providers/Microsoft.EventGrid/eventSubscriptions/to-queue","route":"to-queue","source":"stfunc (Microsoft.Storage/storageAccounts)","destination":"incoming-events","destination_type":"StorageQueue","classification":"supporting-context","source_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc","source_type":"Microsoft.Storage/storageAccounts","destination_target_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events","external_delivery":false,"provisioning_state":"Succeeded","event_delivery_schema":"EventGridSchema","included_event_types":["Microsoft.Storage.BlobCreated"],"summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events"]}],"findings":[],"issues":[],"metadata":{"command":"event-grid","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-event-grid-context.json"), liveEventGridContextArtifact{
		Routes: []liveEventGridTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/providers/Microsoft.EventGrid/eventSubscriptions/to-queue",
			Name:                "to-queue",
			Classification:      "supporting-context",
			SourceID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc",
			SourceType:          "Microsoft.Storage/storageAccounts",
			DestinationType:     "StorageQueue",
			DestinationTargetID: "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events",
			ExternalDelivery:    false,
			ProvisioningState:   "Succeeded",
			EventDeliverySchema: "EventGridSchema",
			IncludedEventTypes:  []string{"Microsoft.Storage.BlobCreated"},
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events",
			},
		}},
	}); err != nil {
		t.Fatalf("write event-grid context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected event-grid seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsEventGridClassificationDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-event-grid-classification-drift-test",
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
		RunID:      "live-event-grid-classification-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "event-grid",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/event-grid/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "event-grid", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"routes":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/providers/Microsoft.EventGrid/eventSubscriptions/to-queue","route":"to-queue","destination_type":"StorageQueue","classification":"execution-capable","source_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc","source_type":"Microsoft.Storage/storageAccounts","destination_target_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events","external_delivery":false,"provisioning_state":"Succeeded","event_delivery_schema":"EventGridSchema","included_event_types":["Microsoft.Storage.BlobCreated"],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events"]}],"findings":[],"issues":[],"metadata":{"command":"event-grid","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-event-grid-context.json"), liveEventGridContextArtifact{
		Routes: []liveEventGridTruth{{
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/providers/Microsoft.EventGrid/eventSubscriptions/to-queue",
			Name:                "to-queue",
			Classification:      "supporting-context",
			SourceID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc",
			SourceType:          "Microsoft.Storage/storageAccounts",
			DestinationType:     "StorageQueue",
			DestinationTargetID: "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events",
			ExternalDelivery:    false,
			ProvisioningState:   "Succeeded",
			EventDeliverySchema: "EventGridSchema",
			IncludedEventTypes:  []string{"Microsoft.Storage.BlobCreated"},
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Storage/storageAccounts/stfunc/queueServices/default/queues/incoming-events",
			},
		}},
	}); err != nil {
		t.Fatalf("write event-grid context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected event-grid classification drift finding, got %#v", summary.Findings)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "classification") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected event-grid classification drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsAzureMLAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-azure-ml-pass-test",
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
		RunID:      "live-azure-ml-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "azure-ml",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/azure-ml/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "azure-ml", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workspaces":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops","workspace":"aml-ops","runtime":"compute=1","identity":"SystemAssigned","storage":"datastores=1; storage-account; key-vault; container-registry","classification":"execution-capable","resource_group":"rg-ops","location":"centralus","workspace_kind":"Default","state":"Succeeded","public_network_access":"Enabled","identity_type":"SystemAssigned","principal_id":"principal-123","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system"],"compute_count":1,"compute_types":["AmlCompute"],"job_count":0,"job_types":[],"schedule_count":0,"schedule_trigger_types":[],"endpoint_count":0,"endpoint_auth_modes":[],"endpoint_public_access":[],"datastore_count":1,"datastore_types":["AzureBlob"],"storage_account_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","key_vault_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open","container_registry_id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain","application_insights_id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml","summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system","/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/datastores/labproofblob"]}],"findings":[],"issues":[],"metadata":{"command":"azure-ml","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-azure-ml-context.json"), liveAzureMLContextArtifact{
		Workspaces: []liveAzureMLTruth{{
			ID:                    "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops",
			Name:                  "aml-ops",
			Classification:        "execution-capable",
			ResourceGroup:         "rg-ops",
			Location:              "centralus",
			WorkspaceKind:         "Default",
			State:                 "Succeeded",
			PublicNetworkAccess:   "Enabled",
			IdentityType:          "SystemAssigned",
			PrincipalID:           "principal-123",
			IdentityIDs:           []string{"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system"},
			ComputeCount:          1,
			ComputeTypes:          []string{"AmlCompute"},
			JobCount:              0,
			JobTypes:              []string{},
			ScheduleCount:         0,
			ScheduleTriggerTypes:  []string{},
			EndpointCount:         0,
			EndpointAuthModes:     []string{},
			EndpointPublicAccess:  []string{},
			DatastoreCount:        1,
			DatastoreTypes:        []string{"AzureBlob"},
			StorageAccountID:      "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
			KeyVaultID:            "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open",
			ContainerRegistryID:   "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain",
			ApplicationInsightsID: "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system",
				"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
				"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/datastores/labproofblob",
			},
		}},
	}); err != nil {
		t.Fatalf("write azure-ml context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected azure-ml seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsAzureMLClassificationDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-azure-ml-classification-drift-test",
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
		RunID:      "live-azure-ml-classification-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "azure-ml",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/azure-ml/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "azure-ml", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"workspaces":[{"id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops","workspace":"aml-ops","classification":"supporting-context","resource_group":"rg-ops","location":"centralus","workspace_kind":"Default","state":"Succeeded","public_network_access":"Enabled","identity_type":"SystemAssigned","principal_id":"principal-123","identity_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system"],"compute_count":1,"compute_types":["AmlCompute"],"job_count":0,"job_types":[],"schedule_count":0,"schedule_trigger_types":[],"endpoint_count":0,"endpoint_auth_modes":[],"endpoint_public_access":[],"datastore_count":1,"datastore_types":["AzureBlob"],"storage_account_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","key_vault_id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open","container_registry_id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain","application_insights_id":"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml","related_ids":["/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system","/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml","/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/datastores/labproofblob"]}],"findings":[],"issues":[],"metadata":{"command":"azure-ml","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-azure-ml-context.json"), liveAzureMLContextArtifact{
		Workspaces: []liveAzureMLTruth{{
			ID:                    "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops",
			Name:                  "aml-ops",
			Classification:        "execution-capable",
			ResourceGroup:         "rg-ops",
			Location:              "centralus",
			WorkspaceKind:         "Default",
			State:                 "Succeeded",
			PublicNetworkAccess:   "Enabled",
			IdentityType:          "SystemAssigned",
			PrincipalID:           "principal-123",
			IdentityIDs:           []string{"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system"},
			ComputeCount:          1,
			ComputeTypes:          []string{"AmlCompute"},
			JobCount:              0,
			JobTypes:              []string{},
			ScheduleCount:         0,
			ScheduleTriggerTypes:  []string{},
			EndpointCount:         0,
			EndpointAuthModes:     []string{},
			EndpointPublicAccess:  []string{},
			DatastoreCount:        1,
			DatastoreTypes:        []string{"AzureBlob"},
			StorageAccountID:      "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
			KeyVaultID:            "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open",
			ContainerRegistryID:   "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain",
			ApplicationInsightsID: "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/identities/system",
				"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
				"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-open",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.ContainerRegistry/registries/acrmain",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Insights/components/appi-aml",
				"/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.MachineLearningServices/workspaces/aml-ops/datastores/labproofblob",
			},
		}},
	}); err != nil {
		t.Fatalf("write azure-ml context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected azure-ml classification drift finding, got %#v", summary.Findings)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "classification") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected azure-ml classification drift finding, got %#v", summary.Findings)
	}
}
